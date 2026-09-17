package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Sandbox interface {
	Execute(ctx context.Context, command string, opts SandboxOpts) (*SandboxResult, error)
	CreateContainer(ctx context.Context, opts SandboxOpts) (string, error)
	ExecInContainer(ctx context.Context, containerID, command string) (*SandboxResult, error)
	DestroyContainer(ctx context.Context, containerID string) error
	ListContainers(ctx context.Context) ([]ContainerInfo, error)
}

type SandboxOpts struct {
	Image          string
	MemoryLimitMB  int
	CPULimit       float64
	NetworkEnabled bool
	ReadOnlyRootfs bool
	Timeout        time.Duration
	WorkingDir     string
	Env            map[string]string
}

type SandboxResult struct {
	ContainerID string
	ExitCode    int
	Stdout      string
	Stderr      string
	Duration    time.Duration
	Error       string
}

type ContainerInfo struct {
	ID    string
	State string
	Image string
}

type DockerSocker struct {
	socketPath string
	client     *http.Client
}

// NewDockerSandbox returns a Sandbox backed by the Docker Engine API over a
// unix socket. WARNING: access to /var/run/docker.sock is effectively root on
// the host — only enable this backend (OVARA_SANDBOX_ENABLED=true) when the
// gateway itself runs in a trusted context. Containers created here drop all
// capabilities, set no-new-privileges, and default to NetworkMode=none unless
// SandboxOpts.NetworkEnabled is set.
func NewDockerSandbox(socketPath string) *DockerSocker {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	return &DockerSocker{
		socketPath: socketPath,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
			Timeout: 30 * time.Second,
		},
	}
}

func (d *DockerSocker) Execute(ctx context.Context, command string, opts SandboxOpts) (*SandboxResult, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	containerID, err := d.CreateContainer(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	defer d.DestroyContainer(context.Background(), containerID)

	return d.ExecInContainer(ctx, containerID, command)
}

func (d *DockerSocker) CreateContainer(ctx context.Context, opts SandboxOpts) (string, error) {
	image := opts.Image
	if image == "" {
		image = "alpine:latest"
	}

	// Docker Engine API: POST /containers/create takes container config
	// fields at the top level, with runtime options under "HostConfig".
	body := map[string]interface{}{
		"Image": image,
		"Cmd":   []string{"sh", "-c", "sleep 3600"},
		"Env":   envToSlice(opts.Env),
		"HostConfig": map[string]interface{}{
			"ReadonlyRootfs": opts.ReadOnlyRootfs,
			// Drop all Linux capabilities and apply the default seccomp
			// profile: the sandboxed workload should not need any caps.
			"CapDrop":     []string{"ALL"},
			"SecurityOpt": []string{"no-new-privileges"},
		},
	}

	if opts.MemoryLimitMB > 0 {
		body["HostConfig"].(map[string]interface{})["Memory"] = opts.MemoryLimitMB * 1024 * 1024
	}

	if !opts.NetworkEnabled {
		body["HostConfig"].(map[string]interface{})["NetworkMode"] = "none"
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	resp, err := d.dockerPost(ctx, "/containers/create?restart=no", data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("docker create returned %d: failed to read response body: %w", resp.StatusCode, err)
		}
		return "", fmt.Errorf("docker create returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Id       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	startResp, err := d.dockerPost(ctx, "/containers/"+result.Id+"/start", nil)
	if err != nil {
		return "", fmt.Errorf("start container: %w", err)
	}
	startResp.Body.Close()

	return result.Id, nil
}

func (d *DockerSocker) ExecInContainer(ctx context.Context, containerID, command string) (*SandboxResult, error) {
	start := time.Now()

	execConfig := map[string]interface{}{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          []string{"sh", "-c", command},
	}

	data, err := json.Marshal(execConfig)
	if err != nil {
		return nil, err
	}

	resp, err := d.dockerPost(ctx, "/containers/"+containerID+"/exec", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("docker exec create returned %d: %s", resp.StatusCode, string(respBody))
	}

	var execResult struct {
		Id string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execResult); err != nil {
		return nil, err
	}
	if execResult.Id == "" {
		return nil, fmt.Errorf("docker exec create returned empty exec id")
	}

	startResp, err := d.dockerPost(ctx, "/exec/"+execResult.Id+"/start", map[string]interface{}{
		"Detach": false,
		"Tty":    false,
	})
	if err != nil {
		return nil, err
	}
	defer startResp.Body.Close()

	if startResp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(startResp.Body)
		return nil, fmt.Errorf("docker exec start returned %d: %s", startResp.StatusCode, string(respBody))
	}

	raw, err := io.ReadAll(startResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading exec output: %w", err)
	}

	// The exec start response is a docker-multiplexed stream: each frame is an
	// 8-byte header [stream_id, 0,0,0, size(4, big-endian)] followed by payload.
	// stream_id 1 = stdout, 2 = stderr. Demux it into separate buffers.
	stdout, stderr := demuxDockerStream(raw)

	// The exec start response carries multiplexed output but no exit code;
	// GET /exec/{id}/json reports the real ExitCode.
	exitCode, err := d.execExitCode(ctx, execResult.Id)
	if err != nil {
		return nil, fmt.Errorf("inspect exec: %w", err)
	}

	return &SandboxResult{
		ContainerID: containerID,
		ExitCode:    exitCode,
		Stdout:      stdout.String(),
		Stderr:      stderr.String(),
		Duration:    time.Since(start),
	}, nil
}

// demuxDockerStream splits a raw docker attach/exec output stream into
// stdout and stderr. Frames have an 8-byte header: byte 0 is the stream id
// (1=stdout, 2=stderr), bytes 4-7 are the big-endian payload length. If the
// stream does not look multiplexed (e.g. TTY mode), the whole payload is
// treated as stdout.
func demuxDockerStream(raw []byte) (stdout, stderr *bytes.Buffer) {
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	i := 0
	for i+8 <= len(raw) {
		streamID := raw[i]
		if streamID != 1 && streamID != 2 {
			// Not a multiplexed stream — treat remainder as stdout.
			stdout.Write(raw[i:])
			return stdout, stderr
		}
		size := int(binary.BigEndian.Uint32(raw[i+4 : i+8]))
		i += 8
		if size < 0 || i+size > len(raw) {
			// Truncated/corrupt frame — emit what remains as stdout.
			stdout.Write(raw[i:])
			return stdout, stderr
		}
		if streamID == 1 {
			stdout.Write(raw[i : i+size])
		} else {
			stderr.Write(raw[i : i+size])
		}
		i += size
	}
	if i < len(raw) {
		stdout.Write(raw[i:])
	}
	return stdout, stderr
}

func (d *DockerSocker) execExitCode(ctx context.Context, execID string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/exec/"+execID+"/json", nil)
	if err != nil {
		return 0, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("exec inspect returned %d: %s", resp.StatusCode, string(respBody))
	}

	var inspect struct {
		ExitCode int `json:"ExitCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return 0, err
	}
	return inspect.ExitCode, nil
}

func (d *DockerSocker) DestroyContainer(ctx context.Context, containerID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", "http://localhost/containers/"+containerID+"?force=true", nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (d *DockerSocker) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json?all=true", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containers []struct {
		ID    string   `json:"Id"`
		State string   `json:"State"`
		Names []string `json:"Names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}

	var result []ContainerInfo
	for _, c := range containers {
		result = append(result, ContainerInfo{
			ID:    c.ID,
			State: c.State,
		})
	}
	return result, nil
}

func (d *DockerSocker) dockerPost(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost"+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return d.client.Do(req)
}

func envToSlice(env map[string]string) []string {
	if env == nil {
		return nil
	}
	var result []string
	for k, v := range env {
		result = append(result, k+"="+v)
	}
	return result
}

// NoopSandbox is a placeholder that reports an error rather than pretending
// a command ran successfully — callers must not mistake a no-op for a real
// execution.
type NoopSandbox struct{}

var errSandboxNotConfigured = fmt.Errorf("sandbox backend not configured: command not executed")

func (n *NoopSandbox) Execute(ctx context.Context, command string, opts SandboxOpts) (*SandboxResult, error) {
	return nil, errSandboxNotConfigured
}

func (n *NoopSandbox) CreateContainer(ctx context.Context, opts SandboxOpts) (string, error) {
	return "", errSandboxNotConfigured
}

func (n *NoopSandbox) ExecInContainer(ctx context.Context, containerID, command string) (*SandboxResult, error) {
	return nil, errSandboxNotConfigured
}

func (n *NoopSandbox) DestroyContainer(ctx context.Context, containerID string) error {
	return nil
}

func (n *NoopSandbox) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	return nil, nil
}

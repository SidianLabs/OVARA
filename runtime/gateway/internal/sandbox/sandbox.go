package sandbox

import (
	"bytes"
	"context"
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

	config := map[string]interface{}{
		"Image": image,
		"Cmd":   []string{"sh", "-c", "sleep 3600"},
		"Env":   envToSlice(opts.Env),
	}

	hostConfig := map[string]interface{}{
		"ReadonlyRootfs": opts.ReadOnlyRootfs,
	}

	if opts.MemoryLimitMB > 0 {
		hostConfig["Memory"] = opts.MemoryLimitMB * 1024 * 1024
	}

	if !opts.NetworkEnabled {
		hostConfig["NetworkMode"] = "none"
	}

	body := map[string]interface{}{
		"config":     config,
		"hostConfig": hostConfig,
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
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("docker create returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Id       string `json:"Id"`
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

	var execResult struct {
		Id string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execResult); err != nil {
		return nil, err
	}

	startResp, err := d.dockerPost(ctx, "/exec/"+execResult.Id+"/start", map[string]interface{}{
		"Detach": false,
		"Tty":    false,
	})
	if err != nil {
		return nil, err
	}
	defer startResp.Body.Close()

	output, _ := io.ReadAll(startResp.Body)

	return &SandboxResult{
		ContainerID: containerID,
		ExitCode:    0,
		Stdout:      string(output),
		Duration:    time.Since(start),
	}, nil
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

type NoopSandbox struct{}

func (n *NoopSandbox) Execute(ctx context.Context, command string, opts SandboxOpts) (*SandboxResult, error) {
	return &SandboxResult{
		ExitCode: 0,
		Stdout:   "noop: command not executed",
	}, nil
}

func (n *NoopSandbox) CreateContainer(ctx context.Context, opts SandboxOpts) (string, error) {
	return "noop-container", nil
}

func (n *NoopSandbox) ExecInContainer(ctx context.Context, containerID, command string) (*SandboxResult, error) {
	return &SandboxResult{
		ContainerID: containerID,
		ExitCode:    0,
		Stdout:      "noop: command not executed",
	}, nil
}

func (n *NoopSandbox) DestroyContainer(ctx context.Context, containerID string) error {
	return nil
}

func (n *NoopSandbox) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	return nil, nil
}

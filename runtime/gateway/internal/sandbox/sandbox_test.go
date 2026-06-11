package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestNewDockerSandbox_Default(t *testing.T) {
	s := NewDockerSandbox("")
	if s.socketPath != "/var/run/docker.sock" {
		t.Errorf("default socket path = %v, want /var/run/docker.sock", s.socketPath)
	}
}

func TestNewDockerSandbox_Custom(t *testing.T) {
	s := NewDockerSandbox("/tmp/docker.sock")
	if s.socketPath != "/tmp/docker.sock" {
		t.Errorf("socket path = %v, want /tmp/docker.sock", s.socketPath)
	}
}

func TestSandboxOpts_Defaults(t *testing.T) {
	opts := SandboxOpts{}
	if opts.Image != "" {
		t.Errorf("default image = %v, want empty", opts.Image)
	}
	if opts.MemoryLimitMB != 0 {
		t.Errorf("default memory = %v, want 0", opts.MemoryLimitMB)
	}
}

func TestEnvToSlice(t *testing.T) {
	env := map[string]string{"FOO": "bar", "BAZ": "qux"}
	slice := envToSlice(env)
	if len(slice) != 2 {
		t.Fatalf("len = %d, want 2", len(slice))
	}
	found := map[string]bool{}
	for _, s := range slice {
		found[s] = true
	}
	if !found["FOO=bar"] || !found["BAZ=qux"] {
		t.Errorf("unexpected slice: %v", slice)
	}
}

func TestEnvToSlice_Nil(t *testing.T) {
	slice := envToSlice(nil)
	if slice != nil {
		t.Errorf("nil env = %v, want nil", slice)
	}
}

func TestEnvToSlice_Empty(t *testing.T) {
	slice := envToSlice(map[string]string{})
	if slice != nil {
		t.Errorf("empty env = %v, want nil", slice)
	}
}

func TestNoopSandbox_Execute(t *testing.T) {
	s := &NoopSandbox{}
	ctx := context.Background()
	result, err := s.Execute(ctx, "echo hello", SandboxOpts{})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
	if result.Stdout != "noop: command not executed" {
		t.Errorf("stdout = %v", result.Stdout)
	}
}

func TestNoopSandbox_CreateContainer(t *testing.T) {
	s := &NoopSandbox{}
	ctx := context.Background()
	id, err := s.CreateContainer(ctx, SandboxOpts{})
	if err != nil {
		t.Fatalf("CreateContainer failed: %v", err)
	}
	if id != "noop-container" {
		t.Errorf("id = %v, want noop-container", id)
	}
}

func TestNoopSandbox_ExecInContainer(t *testing.T) {
	s := &NoopSandbox{}
	ctx := context.Background()
	result, err := s.ExecInContainer(ctx, "test-container", "echo hello")
	if err != nil {
		t.Fatalf("ExecInContainer failed: %v", err)
	}
	if result.ContainerID != "test-container" {
		t.Errorf("container id = %v, want test-container", result.ContainerID)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestNoopSandbox_DestroyContainer(t *testing.T) {
	s := &NoopSandbox{}
	ctx := context.Background()
	err := s.DestroyContainer(ctx, "test-container")
	if err != nil {
		t.Fatalf("DestroyContainer failed: %v", err)
	}
}

func TestNoopSandbox_ListContainers(t *testing.T) {
	s := &NoopSandbox{}
	ctx := context.Background()
	containers, err := s.ListContainers(ctx)
	if err != nil {
		t.Fatalf("ListContainers failed: %v", err)
	}
	if containers != nil {
		t.Errorf("containers = %v, want nil", containers)
	}
}

func TestSandboxResult_Structure(t *testing.T) {
	result := &SandboxResult{
		ContainerID: "abc123",
		ExitCode:    0,
		Stdout:      "hello",
		Stderr:      "",
		Duration:    100 * time.Millisecond,
		Error:       "",
	}
	if result.ContainerID != "abc123" {
		t.Errorf("container id = %v", result.ContainerID)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d", result.ExitCode)
	}
}

func TestContainerInfo_Structure(t *testing.T) {
	info := ContainerInfo{
		ID:    "container-1",
		State: "running",
		Image: "alpine:latest",
	}
	if info.ID != "container-1" {
		t.Errorf("id = %v", info.ID)
	}
	if info.State != "running" {
		t.Errorf("state = %v", info.State)
	}
}

func TestDockerSocker_DockerPost_InvalidBody(t *testing.T) {
	s := NewDockerSandbox("/nonexistent.sock")
	_, err := s.dockerPost(context.Background(), "/test", make(chan int))
	if err == nil {
		t.Error("expected error for invalid body type")
	}
}

func TestSandboxInterface(t *testing.T) {
	var _ Sandbox = &NoopSandbox{}
}

func TestSandboxOpts_WithAllOptions(t *testing.T) {
	opts := SandboxOpts{
		Image:          "ubuntu:20.04",
		MemoryLimitMB:  1024,
		CPULimit:       2.0,
		NetworkEnabled: false,
		ReadOnlyRootfs: true,
		Timeout:        30 * time.Second,
		WorkingDir:     "/workspace",
		Env:            map[string]string{"FOO": "bar"},
	}
	if opts.Image != "ubuntu:20.04" {
		t.Errorf("image = %v", opts.Image)
	}
	if opts.MemoryLimitMB != 1024 {
		t.Errorf("memory = %d", opts.MemoryLimitMB)
	}
	if opts.NetworkEnabled {
		t.Error("network should be disabled")
	}
	if !opts.ReadOnlyRootfs {
		t.Error("rootfs should be read-only")
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("timeout = %v", opts.Timeout)
	}
	if opts.WorkingDir != "/workspace" {
		t.Errorf("working dir = %v", opts.WorkingDir)
	}
	if opts.Env["FOO"] != "bar" {
		t.Errorf("env = %v", opts.Env)
	}
}

func TestSandboxResult_Error(t *testing.T) {
	result := &SandboxResult{
		ContainerID: "test",
		ExitCode:    1,
		Error:       "command failed",
	}
	if result.Error != "command failed" {
		t.Errorf("error = %v", result.Error)
	}
	if result.ExitCode != 1 {
		t.Errorf("exit code = %d", result.ExitCode)
	}
}

func TestSandboxResult_Duration(t *testing.T) {
	result := &SandboxResult{
		Duration: 150 * time.Millisecond,
	}
	if result.Duration != 150*time.Millisecond {
		t.Errorf("duration = %v", result.Duration)
	}
}
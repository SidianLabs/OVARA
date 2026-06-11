package sandbox

import (
	"context"
	"testing"
)

func TestNoopSandbox_Execute(t *testing.T) {
	s := &NoopSandbox{}
	result, err := s.Execute(context.Background(), "echo hello", SandboxOpts{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestNoopSandbox_CreateContainer(t *testing.T) {
	s := &NoopSandbox{}
	id, err := s.CreateContainer(context.Background(), SandboxOpts{Image: "alpine:latest"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if id != "noop-container" {
		t.Errorf("id = %q, want %q", id, "noop-container")
	}
}

func TestNoopSandbox_ExecInContainer(t *testing.T) {
	s := &NoopSandbox{}
	result, err := s.ExecInContainer(context.Background(), "test-container", "ls")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestNoopSandbox_DestroyContainer(t *testing.T) {
	s := &NoopSandbox{}
	err := s.DestroyContainer(context.Background(), "test-container")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoopSandbox_ListContainers(t *testing.T) {
	s := &NoopSandbox{}
	containers, err := s.ListContainers(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if containers != nil {
		t.Errorf("expected nil, got %v", containers)
	}
}

func TestEnvToSlice(t *testing.T) {
	env := map[string]string{
		"HOME": "/root",
		"PATH": "/usr/bin",
	}
	slice := envToSlice(env)
	if len(slice) != 2 {
		t.Errorf("len = %d, want 2", len(slice))
	}
}

func TestEnvToSlice_Nil(t *testing.T) {
	slice := envToSlice(nil)
	if slice != nil {
		t.Errorf("expected nil, got %v", slice)
	}
}

func TestSandboxOpts_Defaults(t *testing.T) {
	opts := SandboxOpts{
		Image:          "alpine:latest",
		MemoryLimitMB:  128,
		CPULimit:       0.5,
		NetworkEnabled: false,
		ReadOnlyRootfs: true,
	}

	if opts.Image != "alpine:latest" {
		t.Errorf("image = %q", opts.Image)
	}
	if opts.MemoryLimitMB != 128 {
		t.Errorf("memory = %d", opts.MemoryLimitMB)
	}
	if opts.NetworkEnabled {
		t.Error("network should be disabled")
	}
}

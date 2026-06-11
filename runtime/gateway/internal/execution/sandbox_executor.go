package execution

import (
	"context"
	"time"

	"ovara.runtime.gateway/internal/sandbox"
)

type SandboxExecutor struct {
	sandbox     sandbox.Sandbox
	timeout     time.Duration
	image       string
	networkOff  bool
}

func NewSandboxExecutor(s sandbox.Sandbox, timeoutSec int) *SandboxExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	return &SandboxExecutor{
		sandbox:    s,
		timeout:    time.Duration(timeoutSec) * time.Second,
		image:      "alpine:latest",
		networkOff: true,
	}
}

func (se *SandboxExecutor) SetImage(image string) {
	se.image = image
}

func (se *SandboxExecutor) SetNetworkDisabled(disabled bool) {
	se.networkOff = disabled
}

func (se *SandboxExecutor) Execute(ctx context.Context, e *Execution) error {
	e.MarkStarted()

	timeout := se.timeout
	if e.TimeoutSeconds > 0 {
		timeout = time.Duration(e.TimeoutSeconds) * time.Second
	}

	opts := sandbox.SandboxOpts{
		Image:          se.image,
		Timeout:        timeout,
		NetworkEnabled: !se.networkOff,
		ReadOnlyRootfs: true,
	}

	result, err := se.sandbox.Execute(ctx, e.Resource, opts)
	if err != nil {
		e.MarkFailed("sandbox error: "+err.Error(), 1)
		return err
	}

	if result.Error != "" {
		e.MarkFailed(result.Error, result.ExitCode)
	} else {
		e.MarkSucceeded(result.ExitCode, result.Stdout, result.Stderr)
	}
	return nil
}

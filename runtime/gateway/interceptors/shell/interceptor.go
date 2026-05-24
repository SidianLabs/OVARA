package shell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/client"
	"ovara.runtime.gateway/internal/models"
)

type Interceptor struct {
	gatewayURL string
	agentID    string
	client    *client.GatewayClient
	timeout   time.Duration
	env       []string
	dir       string
}

type Option func(*Interceptor)

func WithTimeout(d time.Duration) Option {
	return func(i *Interceptor) {
		i.timeout = d
	}
}

func WithEnv(env []string) Option {
	return func(i *Interceptor) {
		i.env = env
	}
}

func WithDir(dir string) Option {
	return func(i *Interceptor) {
		i.dir = dir
	}
}

func New(gatewayURL, agentID string, opts ...Option) *Interceptor {
	i := &Interceptor{
		gatewayURL: gatewayURL,
		agentID:    agentID,
		timeout:    30 * time.Second,
	}
	for _, opt := range opts {
		opt(i)
	}
	i.client = client.NewGatewayClient(gatewayURL, agentID)
	return i
}

type Action struct {
	Command  string
	Resource string
	Env      []string
	Dir      string
	Metadata map[string]any
}

func (i *Interceptor) normaliseAction(cmd string, opts ...ActionOption) *models.ActionRequest {
	action := &Action{Command: cmd}
	for _, opt := range opts {
		opt(action)
	}

	resource := action.Resource
	if resource == "" {
		resource = "shell:" + cmd
	}

	return &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    resource,
		Environment: models.EnvironmentLocal,
		Metadata:    encodeMetadata(action.Metadata),
	}
}

func encodeMetadata(m map[string]any) json.RawMessage {
	if m == nil {
		return nil
	}
	data, _ := json.Marshal(m)
	return data
}

type ActionOption func(*Action)

func WithResource(resource string) ActionOption {
	return func(a *Action) {
		a.Resource = resource
	}
}

func WithShellMetadata(metadata map[string]any) ActionOption {
	return func(a *Action) {
		a.Metadata = metadata
	}
}

type Result struct {
	Decision   models.Decision
	Output     []byte
	ExitCode   int
	Error      error
	DecisionID string
}

func (i *Interceptor) Execute(ctx context.Context, cmd string, opts ...ActionOption) *Result {
	actionReq := i.normaliseAction(cmd, opts...)

	resp, err := i.client.Check(actionReq.ActionType, actionReq.Resource, actionReq.Environment)
	if err != nil {
		return &Result{
			Decision: models.DecisionDeny,
			Error:    fmt.Errorf("gateway check failed: %w", err),
		}
	}

	if resp.Decision == models.DecisionDeny {
		return &Result{
			Decision:   models.DecisionDeny,
			DecisionID: resp.DecisionID,
			Error:      fmt.Errorf("action denied: %v", resp.ReasonCodes),
		}
	}

	if resp.Decision == models.DecisionEscalate {
		return &Result{
			Decision:   models.DecisionEscalate,
			DecisionID: resp.DecisionID,
			Error:      fmt.Errorf("action requires approval: %v", resp.ReasonCodes),
		}
	}

	execCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	execCmd := exec.CommandContext(execCtx, "sh", "-c", cmd)
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr
	if len(i.env) > 0 {
		execCmd.Env = i.env
	}
	if i.dir != "" {
		execCmd.Dir = i.dir
	}

	err = execCmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return &Result{
		Decision:   models.DecisionAllow,
		DecisionID: resp.DecisionID,
		Output:     stdout.Bytes(),
		ExitCode:   exitCode,
		Error:     err,
	}
}

func ParseCommand(cmd string) (string, []string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}
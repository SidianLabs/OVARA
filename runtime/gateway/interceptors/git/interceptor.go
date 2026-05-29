package git

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"ovara.runtime.gateway/internal/client"
	"ovara.runtime.gateway/internal/models"
)

type Interceptor struct {
	gatewayURL string
	agentID    string
	client    *client.GatewayClient
}

func New(gatewayURL, agentID string) *Interceptor {
	return &Interceptor{
		gatewayURL: gatewayURL,
		agentID:    agentID,
		client:    client.NewGatewayClient(gatewayURL, agentID),
	}
}

type Action struct {
	Command        string
	Args           []string
	Repo           string
	Branch         string
	CheckoutBranch string
	Remote         string
	Metadata       map[string]any
}

func (i *Interceptor) normaliseAction(cmd string, args []string, opts ...ActionOption) (*models.ActionRequest, error) {
	action := &Action{Command: cmd, Args: args}
	for _, opt := range opts {
		opt(action)
	}

	actionType := resolveGitActionType(cmd, args)
	resource := action.Repo
	if resource == "" {
		resource = "git:local"
	}

	if action.CheckoutBranch != "" {
		resource += ":" + action.CheckoutBranch
	} else if action.Branch != "" {
		resource += ":branch/" + action.Branch
	}

	return &models.ActionRequest{
		ActionType:  actionType,
		Resource:    resource,
		Environment: models.EnvironmentLocal,
	}, nil
}

func resolveGitActionType(cmd string, args []string) models.ActionType {
	switch cmd {
	case "push":
		if contains(args, "--force") || contains(args, "-f") {
			return models.ActionTypeGitForcePush
		}
		return models.ActionTypeGitPush
	case "pull":
		return models.ActionTypeGitPull
	case "fetch":
		return models.ActionTypeGitFetch
	case "checkout":
		return models.ActionTypeGitCheckout
	default:
		return models.ActionType("git." + cmd)
	}
}

func contains(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}

type ActionOption func(*Action)

func WithRepo(repo string) ActionOption {
	return func(a *Action) {
		a.Repo = repo
	}
}

func WithBranch(branch string) ActionOption {
	return func(a *Action) {
		a.Branch = branch
	}
}

func WithCheckout(branch string) ActionOption {
	return func(a *Action) {
		a.CheckoutBranch = branch
	}
}

type Result struct {
	Decision   models.Decision
	Output     []byte
	ExitCode   int
	Error      error
	DecisionID string
}

func (i *Interceptor) Execute(ctx context.Context, cmd string, args []string, opts ...ActionOption) *Result {
	actionReq, err := i.normaliseAction(cmd, args, opts...)
	if err != nil {
		return &Result{
			Decision: models.DecisionDeny,
			Error:    fmt.Errorf("normalizing git action: %w", err),
		}
	}

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

	execCmd := exec.CommandContext(ctx, cmd, args...)
	out, err := execCmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return &Result{
		Decision:   models.DecisionAllow,
		DecisionID: resp.DecisionID,
		Output:     out,
		ExitCode:   exitCode,
		Error:     err,
	}
}

func ParseArgs(args []string) (gitCmd string, rest []string) {
	if len(args) == 0 {
		return "", nil
	}
	gitIdx := 0
	if args[0] == "git" && len(args) > 1 {
		gitIdx = 1
	}
	if len(args) > gitIdx {
		return args[gitIdx], args[gitIdx+1:]
	}
	return "", nil
}

func GetCurrentRepo() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
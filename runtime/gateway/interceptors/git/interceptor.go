package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"ovara.runtime.gateway/internal/client"
	"ovara.runtime.gateway/internal/models"
)

type Interceptor struct {
	gatewayURL string
	agentID    string
	client     *client.GatewayClient
}

func New(gatewayURL, agentID string) *Interceptor {
	return &Interceptor{
		gatewayURL: gatewayURL,
		agentID:    agentID,
		client:     client.NewGatewayClient(gatewayURL, agentID),
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
		if isForcePush(args) {
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

// isForcePush reports whether the push arguments request any form of forced
// update: -f/--force, --force-with-lease, --force-if-includes, combined short
// flags like -uf/--ff, and --force=<mode>.
func isForcePush(args []string) bool {
	for _, a := range args {
		switch {
		case a == "-f", a == "--force":
			return true
		case strings.HasPrefix(a, "--force"):
			// --force-with-lease, --force-if-includes, --force=...
			return true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
			// Combined short flags: any flag cluster containing 'f' (e.g. -uf).
			for _, c := range a[1:] {
				if c == 'f' {
					return true
				}
			}
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

	// Fail closed: only an explicit "allow" proceeds to execution. Any other
	// or unrecognized decision is treated as denied.
	if resp.Decision != models.DecisionAllow {
		return &Result{
			Decision:   resp.Decision,
			DecisionID: resp.DecisionID,
			Error:      fmt.Errorf("action not allowed (decision=%q): %v", resp.Decision, resp.ReasonCodes),
		}
	}

	execCmd := exec.CommandContext(ctx, gitBinary, append([]string{cmd}, args...)...)
	// Strip dangerous environment overrides so an inherited env cannot redirect
	// git's transport/exec behavior (e.g. GIT_SSH_COMMAND arbitrary commands).
	execCmd.Env = sanitizedEnv()
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
		Error:      err,
	}
}

// gitBinary is the git executable invoked for allowed actions.
const gitBinary = "git"

// gitEnvDenylist lists environment variables removed before spawning git.
// These let a caller hijack transport or code execution (e.g. via SSH command
// injection or exec-path redirection).
var gitEnvDenylist = map[string]bool{
	"GIT_SSH_COMMAND":       true,
	"GIT_SSH":               true,
	"GIT_EXEC_PATH":         true,
	"GIT_PROXY_COMMAND":     true,
	"GIT_EXTERNAL_DIFF":     true,
	"GIT_PAGER":             true,
	"GIT_EDITOR":            true,
	"GIT_ASKPASS":           true,
	"SSH_ASKPASS":           true,
	"GIT_TEMPLATE_DIR":      true,
	"GIT_DIR":               true,
	"GIT_OBJECT_DIRECTORY":  true,
}

// gitEnvDeniedPrefixes are stripped by prefix so entire families of dangerous
// variables cannot be smuggled past the denylist by enumeration:
//   - GIT_CONFIG* lets a caller inject arbitrary git configuration (including
//     core.sshCommand / core.fsmonitor hooks) via env (GIT_CONFIG_COUNT,
//     GIT_CONFIG_KEY_*, GIT_CONFIG_VALUE_*, GIT_CONFIG_PARAMETERS, etc.)
//   - LD_*/DYLD_* are dynamic-loader variables (LD_PRELOAD, LD_AUDIT,
//     DYLD_INSERT_LIBRARIES, ...) that inject code into the spawned binary.
var gitEnvDeniedPrefixes = []string{
	"GIT_CONFIG",
	"LD_",
	"DYLD_",
}

func gitEnvDenied(name string) bool {
	if gitEnvDenylist[name] {
		return true
	}
	for _, p := range gitEnvDeniedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func sanitizedEnv() []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		name := kv
		if idx := strings.IndexByte(kv, '='); idx >= 0 {
			name = kv[:idx]
		}
		if gitEnvDenied(name) {
			continue
		}
		out = append(out, kv)
	}
	return out
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

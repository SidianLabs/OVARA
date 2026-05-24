package git

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestInterceptor_normaliseAction_Push(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req, err := i.normaliseAction("push", []string{"origin", "main"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ActionType != models.ActionTypeGitPush {
		t.Errorf("action_type = %v, want git.push", req.ActionType)
	}
	if req.Environment != models.EnvironmentLocal {
		t.Errorf("environment = %v, want local", req.Environment)
	}
}

func TestInterceptor_normaliseAction_Pull(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req, err := i.normaliseAction("pull", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ActionType != models.ActionTypeGitPull {
		t.Errorf("action_type = %v, want git.pull", req.ActionType)
	}
}

func TestInterceptor_normaliseAction_ForcePush(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req, err := i.normaliseAction("push", []string{"--force", "origin", "main"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ActionType != models.ActionTypeGitForcePush {
		t.Errorf("action_type = %v, want git.force_push", req.ActionType)
	}
}

func TestInterceptor_normaliseAction_WithRepo(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req, err := i.normaliseAction("push", []string{"origin", "main"}, WithRepo("git:acme/api"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Resource != "git:acme/api" {
		t.Errorf("resource = %v, want git:acme/api", req.Resource)
	}
}

func TestInterceptor_normaliseAction_WithBranch(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req, err := i.normaliseAction("push", []string{"origin", "main"}, WithBranch("feature/test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Resource != "git:local:branch/feature/test" {
		t.Errorf("resource = %v, want git:local:branch/feature/test", req.Resource)
	}
}

func TestInterceptor_Execute_Allow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID: "dec_git_allow",
			Decision:   models.DecisionAllow,
			ReasonCodes: []models.ReasonCode{models.ReasonAllowed},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "push", []string{"origin", "main"}, WithRepo("git:acme/api"))

	if result.Decision != models.DecisionAllow {
		t.Errorf("decision = %v, want allow", result.Decision)
	}
}

func TestInterceptor_Execute_Deny(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID: "dec_git_deny",
			Decision:   models.DecisionDeny,
			ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "push", []string{"--force", "origin", "main"}, WithRepo("git:acme/api"))

	if result.Decision != models.DecisionDeny {
		t.Errorf("decision = %v, want deny", result.Decision)
	}
	if result.Error == nil {
		t.Error("expected error for denied action")
	}
}

func TestInterceptor_Execute_Escalate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID:       "dec_git_esc",
			Decision:         models.DecisionEscalate,
			ReasonCodes:      []models.ReasonCode{models.ReasonEscalate},
			RequiresApproval: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "push", []string{"origin", "main"}, WithRepo("git:acme/api"))

	if result.Decision != models.DecisionEscalate {
		t.Errorf("decision = %v, want escalate", result.Decision)
	}
	if result.Error == nil {
		t.Error("expected error for escalated action")
	}
}

func TestInterceptor_Execute_GatewayError(t *testing.T) {
	i := New("http://localhost:9999", "test-agent")
	result := i.Execute(context.Background(), "pull", []string{})

	if result.Decision != models.DecisionDeny {
		t.Errorf("decision = %v, want deny when gateway unreachable", result.Decision)
	}
}

func TestResolveGitActionType(t *testing.T) {
	tests := []struct {
		cmd  string
		args []string
		want models.ActionType
	}{
		{"push", []string{}, models.ActionTypeGitPush},
		{"push", []string{"origin", "main"}, models.ActionTypeGitPush},
		{"push", []string{"--force", "origin"}, models.ActionTypeGitForcePush},
		{"push", []string{"-f", "origin"}, models.ActionTypeGitForcePush},
		{"pull", []string{}, models.ActionTypeGitPull},
		{"clone", []string{}, models.ActionType("git.clone")},
	}

	for _, tt := range tests {
		got := resolveGitActionType(tt.cmd, tt.args)
		if got != tt.want {
			t.Errorf("resolveGitActionType(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"--force", "origin"}, "--force") {
		t.Error("expected --force to be found")
	}
	if contains([]string{"origin", "main"}, "--force") {
		t.Error("expected --force not to be found")
	}
}

func TestParseArgs(t *testing.T) {
	cmd, rest := ParseArgs([]string{"git", "push", "origin", "main"})
	if cmd != "push" {
		t.Errorf("cmd = %v, want push", cmd)
	}
	if len(rest) != 2 || rest[0] != "origin" || rest[1] != "main" {
		t.Errorf("rest = %v, want [origin main]", rest)
	}
}

func TestParseArgs_Empty(t *testing.T) {
	cmd, rest := ParseArgs([]string{})
	if cmd != "" {
		t.Errorf("cmd = %v, want empty", cmd)
	}
	if rest != nil {
		t.Errorf("rest = %v, want nil", rest)
	}
}
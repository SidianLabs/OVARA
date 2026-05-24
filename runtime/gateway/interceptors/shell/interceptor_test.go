package shell

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestInterceptor_normaliseAction(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req := i.normaliseAction("echo hello")
	if req.ActionType != models.ActionTypeShell {
		t.Errorf("action_type = %v, want shell", req.ActionType)
	}
	if req.Resource == "" {
		t.Error("resource should not be empty")
	}
	if req.Environment != models.EnvironmentLocal {
		t.Errorf("environment = %v, want local", req.Environment)
	}
}

func TestInterceptor_normaliseActionWithResource(t *testing.T) {
	i := New("http://localhost:8080", "test-agent")

	req := i.normaliseAction("rm -rf /", WithResource("shell:dangerous"))
	if req.Resource != "shell:dangerous" {
		t.Errorf("resource = %v, want shell:dangerous", req.Resource)
	}
}

func TestInterceptor_Execute_Allow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID: "dec_allow123",
			Decision:   models.DecisionAllow,
			ReasonCodes: []models.ReasonCode{models.ReasonAllowed},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "echo hello")

	if result.Decision != models.DecisionAllow {
		t.Errorf("decision = %v, want allow", result.Decision)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", result.ExitCode)
	}
}

func TestInterceptor_Execute_Deny(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID: "dec_deny456",
			Decision:   models.DecisionDeny,
			ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "rm -rf /")

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
			DecisionID:       "dec_esc789",
			Decision:         models.DecisionEscalate,
			ReasonCodes:      []models.ReasonCode{models.ReasonEscalate},
			RequiresApproval: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	i := New(ts.URL, "test-agent")
	result := i.Execute(context.Background(), "git push origin main")

	if result.Decision != models.DecisionEscalate {
		t.Errorf("decision = %v, want escalate", result.Decision)
	}
	if result.Error == nil {
		t.Error("expected error for escalated action")
	}
}

func TestInterceptor_Execute_GatewayError(t *testing.T) {
	i := New("http://localhost:9999", "test-agent")
	result := i.Execute(context.Background(), "echo hello")

	if result.Decision != models.DecisionDeny {
		t.Errorf("decision = %v, want deny when gateway is unreachable", result.Decision)
	}
	if result.Error == nil {
		t.Error("expected error when gateway is unreachable")
	}
}

func TestInterceptor_ParseCommand(t *testing.T) {
	cmd, args := ParseCommand("echo hello world")
	if cmd != "echo" {
		t.Errorf("cmd = %v, want echo", cmd)
	}
	if len(args) != 2 || args[0] != "hello" || args[1] != "world" {
		t.Errorf("args = %v, want [hello world]", args)
	}
}

func TestInterceptor_ParseCommand_Empty(t *testing.T) {
	cmd, _ := ParseCommand("")
	if cmd != "" {
		t.Errorf("cmd = %v, want empty", cmd)
	}
}
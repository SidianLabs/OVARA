package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/policy"
)

func TestHandler_RequiredActionFields_GET(t *testing.T) {
	cfg := config.Default()
	store := policy.NewStore("v1-test")
	eval := evaluator.New(store)
	h := New(eval, nil, cfg, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/required_action_fields", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp RequiredActionFieldsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.ActionType.Required {
		t.Error("expected action_type to be required")
	}
	if len(resp.ActionType.AllowedValues) == 0 {
		t.Error("expected action_type to have allowed values")
	}
	if !resp.Environment.Required {
		t.Error("expected environment to be required")
	}
	if !resp.Resource.Required {
		t.Error("expected resource to be required")
	}
	if resp.AgentIdentity.Required {
		t.Error("expected agent_identity to be optional")
	}
	if len(resp.SupportedActionTypes) == 0 {
		t.Error("expected supported_action_types to be non-empty")
	}
	if len(resp.SupportedEnvironments) == 0 {
		t.Error("expected supported_environments to be non-empty")
	}
}

func TestHandler_RequiredActionFields_MethodNotAllowed(t *testing.T) {
	cfg := config.Default()
	store := policy.NewStore("v1-test")
	eval := evaluator.New(store)
	h := New(eval, nil, cfg, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/required_action_fields", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandler_RequiredActionFields_IncludesAllActionTypes(t *testing.T) {
	cfg := config.Default()
	store := policy.NewStore("v1-test")
	eval := evaluator.New(store)
	h := New(eval, nil, cfg, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/required_action_fields", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp RequiredActionFieldsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	required := []string{
		"shell", "exec", "shell.sandboxed",
		"git.push", "git.pull", "git.fetch", "git.checkout",
		"github.push", "github.pr", "github.merge", "github.delete_branch",
		"ci.trigger",
	}
	for _, action := range required {
		found := false
		for _, allowed := range resp.ActionType.AllowedValues {
			if allowed == action {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in supported action types", action)
		}
	}
}

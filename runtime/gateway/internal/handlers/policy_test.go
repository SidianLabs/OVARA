package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/policy"
)

func TestPolicyHandler_Simulate_SingleRequest(t *testing.T) {
	store := policy.NewStore("test")
	store.AddRule(policy.Rule{ActionType: "shell", Environment: "local", Allow: true})
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"request":{"action_type":"shell","resource":"shell:echo hello","environment":"local"},"use_current":true}`

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/simulate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_ListRules(t *testing.T) {
	store := policy.NewStore("v1-test")
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/policy/rules", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_MethodNotAllowed(t *testing.T) {
	h := NewPolicyHandler(nil, policy.NewStore("test"))

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/policy/validate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for GET /v1/policy/validate, got %d", w.Code)
	}
}

func TestPolicyHandler_Simulate_DecisionChanges(t *testing.T) {
	currentStore := policy.NewStore("v1-current")
	currentStore.AddRule(policy.Rule{ActionType: "shell", Environment: "local", Allow: true})

	e := evaluator.New(currentStore)
	h := NewPolicyHandler(e, currentStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	candidateBody := `{"version":"v1-candidate","rules":[{"action_type":"shell","environment":"local","deny":true}]}`

	simReq := map[string]interface{}{
		"request": map[string]interface{}{
			"action_type":  "shell",
			"resource":    "shell:echo hello",
			"environment": "local",
		},
		"candidate_policy": []byte(candidateBody),
	}
	body, _ := json.Marshal(simReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/simulate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyValidator_ValidateRule(t *testing.T) {
	v := policy.NewValidator()

	validRule := &policy.Rule{ActionType: "shell", Environment: "local", Allow: true}
	result := v.ValidateRule(validRule)
	if !result.Valid {
		t.Errorf("expected valid rule to pass: %v", result.Errors)
	}

	emptyActionRule := &policy.Rule{ActionType: "", Environment: "local", Allow: true}
	result = v.ValidateRule(emptyActionRule)
	if result.Valid {
		t.Errorf("expected empty action_type to fail")
	}

	contradictoryRule := &policy.Rule{ActionType: "shell", Environment: "local", Allow: true, Deny: true}
	result = v.ValidateRule(contradictoryRule)
	if result.Valid {
		t.Errorf("expected allow+deny to fail")
	}
}

func TestPolicyValidator_ValidateRules(t *testing.T) {
	v := policy.NewValidator()

	rules := []policy.Rule{
		{ActionType: "shell", Environment: "local", Allow: true},
		{ActionType: "", Environment: "dev", Deny: true},
	}
	result := v.ValidateRules(rules)
	if result.Valid {
		t.Errorf("expected validation to fail with empty action_type")
	}
	if len(result.Errors) < 1 {
		t.Errorf("expected at least 1 error")
	}
}

func TestPolicyHandler_ListHistory(t *testing.T) {
	store := policy.NewStore("v1-test")
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/policy/history", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_GetHistoryEntry_NotFound(t *testing.T) {
	store := policy.NewStore("v1-test")
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/policy/history/entry?id=nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestPolicyHandler_Rollback_NoHistory(t *testing.T) {
	store := policy.NewStore("v1-test")
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rollback", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for empty history, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPolicyHandler_Restore_MissingId(t *testing.T) {
	store := policy.NewStore("v1-test")
	e := evaluator.New(store)
	h := NewPolicyHandler(e, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/policy/restore", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for missing id, got %d: %s", w.Code, w.Body.String())
	}
}

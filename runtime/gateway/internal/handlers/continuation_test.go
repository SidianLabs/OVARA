package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
)

func TestContinuationHandler_HandleList(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c2 := continuation.NewContinuation("dec_2", "git.push", "git:acme/repo").WithAgentID("agt_b")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestContinuationHandler_HandleListFilterByState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_2", "git.push", "git:acme/repo")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?state=approved", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleListFilterByAgent(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_x")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:ls").WithAgentID("agt_y")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?agent_id=agt_x", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleGet(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result continuation.Continuation
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result.State != continuation.StateApproved {
		t.Errorf("state = %v, want approved", result.State)
	}
}

func TestContinuationHandler_HandleGet_NotFound(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/cnt_nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
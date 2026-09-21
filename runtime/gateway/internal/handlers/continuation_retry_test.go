package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
)

func TestContinuationHandler_HandleRetry(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.MarkApproved("admin")
	c.MarkQueued()
	c.State = continuation.StateExecuted
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["state"] != string(continuation.StateResumed) {
		t.Errorf("state = %v, want resumed", resp["state"])
	}
	if resp["retry_count"].(float64) != 1 {
		t.Errorf("retry_count = %v, want 1", resp["retry_count"])
	}

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != continuation.StateResumed {
		t.Errorf("continuation state = %v, want resumed", updated.State)
	}
	if updated.RetryCount != 1 {
		t.Errorf("retry_count = %v, want 1", updated.RetryCount)
	}
}

func TestContinuationHandler_HandleRetry_FromResumedState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.State = continuation.StateResumed
	c.RetryCount = 1
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["retry_count"].(float64) != 2 {
		t.Errorf("retry_count = %v, want 2", resp["retry_count"])
	}

	updated, _ := store.Get(c.ContinuationID)
	if updated.RetryCount != 2 {
		t.Errorf("retry_count = %v, want 2", updated.RetryCount)
	}
}

func TestContinuationHandler_HandleRetry_NotFound(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cnt_nonexistent/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_InvalidState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_DeniedState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateDenied
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_ExpiredState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExpired
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_CancelledState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateCancelled
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_MaxRetriesReached(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	c.RetryCount = 3
	c.MaxRetries = 3
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_ZeroMaxRetries(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	c.MaxRetries = 0
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_MethodNotAllowed(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestContinuationHandler_HandleRetry_FromApprovedState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

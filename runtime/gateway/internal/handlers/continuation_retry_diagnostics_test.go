package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
)

func TestContinuationHandler_HandleGet_IncludesRetryInfo(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 1
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	retry, ok := resp["retry"].(map[string]any)
	if !ok {
		t.Fatal("retry info not present in response")
	}

	canRetry, _ := retry["can_retry"].(bool)
	if !canRetry {
		t.Error("can_retry should be true")
	}

	retryLimitReached, _ := retry["retry_limit_reached"].(bool)
	if retryLimitReached {
		t.Error("retry_limit_reached should be false")
	}

	retriesRemaining, _ := retry["retries_remaining"].(float64)
	if retriesRemaining != 2 {
		t.Errorf("retries_remaining = %v, want 2", retriesRemaining)
	}

	status, _ := retry["status"].(string)
	if status != "retryable" {
		t.Errorf("status = %s, want retryable", status)
	}

	continuation_, ok := resp["continuation"].(map[string]any)
	if !ok {
		t.Fatal("continuation not present in response")
	}
	if continuation_["state"] != string(continuation.StateExecuted) {
		t.Errorf("continuation state = %v, want executed", continuation_["state"])
	}
}

func TestContinuationHandler_HandleGet_RetryInfo_Exhausted(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 3
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	retry, _ := resp["retry"].(map[string]any)
	canRetry, _ := retry["can_retry"].(bool)
	if canRetry {
		t.Error("can_retry should be false")
	}

	retryLimitReached, _ := retry["retry_limit_reached"].(bool)
	if !retryLimitReached {
		t.Error("retry_limit_reached should be true")
	}

	status, _ := retry["status"].(string)
	if status != "exhausted" {
		t.Errorf("status = %s, want exhausted", status)
	}
}

func TestContinuationHandler_HandleGet_RetryInfo_TerminalState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateDenied
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	retry, _ := resp["retry"].(map[string]any)
	status, _ := retry["status"].(string)
	if status != "terminal" {
		t.Errorf("status = %s, want terminal", status)
	}
}

func TestContinuationHandler_HandleList_IncludesRetryableCount(t *testing.T) {
	store := continuation.NewInMemoryStore()

	// Executable but not retryable
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateApproved
	store.Create(c1)

	// Retryable
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:ls")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	c2.RetryCount = 1
	store.Create(c2)

	// Retryable
	c3 := continuation.NewContinuation("dec_3", "shell", "shell:ls")
	c3.State = continuation.StateResumed
	c3.MaxRetries = 3
	c3.RetryCount = 2
	store.Create(c3)

	// Not retryable - exhausted
	c4 := continuation.NewContinuation("dec_4", "shell", "shell:ls")
	c4.State = continuation.StateExecuted
	c4.MaxRetries = 3
	c4.RetryCount = 3
	store.Create(c4)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	retryable, _ := resp["retryable"].(float64)
	if retryable != 2 {
		t.Errorf("retryable = %v, want 2", retryable)
	}

	executable, _ := resp["executable"].(float64)
	if executable != 1 {
		t.Errorf("executable = %v, want 1", executable)
	}

	count, _ := resp["count"].(float64)
	if count != 4 {
		t.Errorf("count = %v, want 4", count)
	}
}

func TestContinuationHandler_HandleList_RetryableCount_Empty(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	retryable, _ := resp["retryable"].(float64)
	if retryable != 0 {
		t.Errorf("retryable = %v, want 0", retryable)
	}
}

func TestContinuationHandler_HandleList_FilterByRetryable_True(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	c1.RetryCount = 1
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	c2.RetryCount = 3
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami")
	c3.State = continuation.StateEscalated
	store.Create(c3)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?retryable=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	continuations, _ := resp["continuations"].([]any)
	if len(continuations) != 1 {
		t.Errorf("count = %d, want 1", len(continuations))
	}
}

func TestContinuationHandler_HandleList_FilterByRetryable_False(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	c1.RetryCount = 1
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	c2.RetryCount = 3
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami")
	c3.State = continuation.StateEscalated
	store.Create(c3)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?retryable=false", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	continuations, _ := resp["continuations"].([]any)
	if len(continuations) != 2 {
		t.Errorf("count = %d, want 2", len(continuations))
	}
}

func TestContinuationHandler_HandleList_CompositeFilter_StateAndRetryable(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	c1.RetryCount = 1
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	c2.RetryCount = 3
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami")
	c3.State = continuation.StateEscalated
	store.Create(c3)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?state=executed&retryable=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	continuations, _ := resp["continuations"].([]any)
	if len(continuations) != 1 {
		t.Errorf("count = %d, want 1", len(continuations))
	}

	count, _ := resp["count"].(float64)
	if count != 1 {
		t.Errorf("count = %v, want 1", count)
	}
}

func TestContinuationHandler_HandleList_RetryableFilter_NoMatch(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 1
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?retryable=false", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	continuations, _ := resp["continuations"].([]any)
	if len(continuations) != 0 {
		t.Errorf("count = %d, want 0", len(continuations))
	}
}

func TestContinuationHandler_HandleList_RetryableFilter_IgnoresInvalidValue(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 1
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?retryable=invalid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	continuations, _ := resp["continuations"].([]any)
	if len(continuations) != 1 {
		t.Errorf("count = %d, want 1 (invalid value should be ignored)", len(continuations))
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/execution"
)

func TestExecutionHandler_HandleGet_IncludesFailureInfo(t *testing.T) {
	store := execution.NewInMemoryStore()
	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	exec, ok := resp["execution"].(map[string]any)
	if !ok {
		t.Fatal("execution not in response")
	}
	if exec["state"] != string(execution.StateFailed) {
		t.Errorf("state = %v, want failed", exec["state"])
	}

	failure, ok := resp["failure"].(map[string]any)
	if !ok {
		t.Fatal("failure not in response")
	}

	category, _ := failure["category"].(string)
	if category != "command_failed" {
		t.Errorf("category = %s, want command_failed", category)
	}

	recoverable, _ := failure["recoverable"].(bool)
	if !recoverable {
		t.Error("recoverable should be true")
	}

	exitCode, _ := failure["exit_code"].(float64)
	if exitCode != 1 {
		t.Errorf("exit_code = %v, want 1", exitCode)
	}
}

func TestExecutionHandler_HandleGet_FailureInfo_Timeout(t *testing.T) {
	store := execution.NewInMemoryStore()
	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:sleep 100", 60)
	e.MarkTimedOut()
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	failure, _ := resp["failure"].(map[string]any)
	category, _ := failure["category"].(string)
	if category != "timeout" {
		t.Errorf("category = %s, want timeout", category)
	}
}

func TestExecutionHandler_HandleGet_FailureInfo_ValidationError(t *testing.T) {
	store := execution.NewInMemoryStore()
	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("invalid shell resource: missing command", 1)
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	failure, _ := resp["failure"].(map[string]any)
	category, _ := failure["category"].(string)
	if category != "validation_error" {
		t.Errorf("category = %s, want validation_error", category)
	}

	recoverable, _ := failure["recoverable"].(bool)
	if recoverable {
		t.Error("recoverable should be false for validation_error")
	}
}

func TestExecutionHandler_HandleList_IncludesSummary(t *testing.T) {
	store := execution.NewInMemoryStore()

	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e1.MarkSucceeded(0, "ok", "")
	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:ls", 60)
	e2.MarkFailed("err", 1)
	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:ls", 60)
	e3.MarkTimedOut()
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	summary, ok := resp["summary"].(map[string]any)
	if !ok {
		t.Fatal("summary not in response")
	}

	total, _ := summary["total"].(float64)
	if total != 3 {
		t.Errorf("total = %v, want 3", total)
	}

	succeeded, _ := summary["succeeded"].(float64)
	if succeeded != 1 {
		t.Errorf("succeeded = %v, want 1", succeeded)
	}

	failed, _ := summary["failed"].(float64)
	if failed != 1 {
		t.Errorf("failed = %v, want 1", failed)
	}

	timedOut, _ := summary["timed_out"].(float64)
	if timedOut != 1 {
		t.Errorf("timed_out = %v, want 1", timedOut)
	}

	running, _ := summary["running"].(float64)
	if running != 0 {
		t.Errorf("running = %v, want 0", running)
	}
}

func TestExecutionHandler_HandleList_EmptySummary(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	summary, _ := resp["summary"].(map[string]any)
	total, _ := summary["total"].(float64)
	if total != 0 {
		t.Errorf("total = %v, want 0", total)
	}
}

func TestExecutionHandler_HandleGet_Success(t *testing.T) {
	store := execution.NewInMemoryStore()
	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkSucceeded(0, "ok", "")
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	failure, _ := resp["failure"].(map[string]any)
	category, _ := failure["category"].(string)
	if category != "success" {
		t.Errorf("category = %s, want success", category)
	}
}

func TestExecutionHandler_HandleGet_WithLinkedContinuation_Retryable(t *testing.T) {
	execStore := execution.NewInMemoryStore()
	contStore := continuation.NewInMemoryStore()

	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.ContinuationID = "cnt_1"
	c.MarkApproved("tester")
	c.MarkQueued()
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 1
	contStore.Create(c)

	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)
	execStore.Create(e)

	h := NewExecutionHandler(execStore)
	h.SetContinuationStore(contStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	retry, ok := resp["retry"].(map[string]any)
	if !ok {
		t.Fatal("retry not in response")
	}

	canRetry, _ := retry["can_retry"].(bool)
	if !canRetry {
		t.Error("can_retry should be true for executed continuation with retries remaining")
	}

	status, _ := retry["status"].(string)
	if status != "retryable" {
		t.Errorf("status = %s, want retryable", status)
	}
}

func TestExecutionHandler_HandleGet_WithLinkedContinuation_Exhausted(t *testing.T) {
	execStore := execution.NewInMemoryStore()
	contStore := continuation.NewInMemoryStore()

	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.ContinuationID = "cnt_1"
	c.MarkApproved("tester")
	c.MarkQueued()
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 3
	contStore.Create(c)

	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)
	execStore.Create(e)

	h := NewExecutionHandler(execStore)
	h.SetContinuationStore(contStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	retry, _ := resp["retry"].(map[string]any)
	canRetry, _ := retry["can_retry"].(bool)
	if canRetry {
		t.Error("can_retry should be false when retry limit reached")
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

func TestExecutionHandler_HandleGet_WithoutContinuationStore(t *testing.T) {
	execStore := execution.NewInMemoryStore()

	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)
	execStore.Create(e)

	h := NewExecutionHandler(execStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["retry"]; ok {
		t.Error("retry should not be present when contStore is nil")
	}
}

func TestExecutionHandler_HandleGet_WithContinuation_ContinuationNotFound(t *testing.T) {
	execStore := execution.NewInMemoryStore()
	contStore := continuation.NewInMemoryStore()

	e := execution.NewExecution("cnt_nonexistent", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)
	execStore.Create(e)

	h := NewExecutionHandler(execStore)
	h.SetContinuationStore(contStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["retry"]; ok {
		t.Error("retry should not be present when continuation not found")
	}
}

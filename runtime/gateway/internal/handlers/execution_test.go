package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/continuation"
	eventsstore "ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type mockExecutor struct {
	resultState  execution.State
	resultExit   int
	resultOutput string
	resultErr    string
	called       int
}

func (m *mockExecutor) Execute(ctx context.Context, e *execution.Execution) error {
	m.called++
	if m.resultState != "" {
		switch m.resultState {
		case execution.StateSucceeded:
			e.MarkSucceeded(m.resultExit, m.resultOutput, m.resultErr)
		case execution.StateFailed:
			e.MarkFailed(m.resultErr, m.resultExit)
		case execution.StateTimedOut:
			e.MarkTimedOut()
		}
	}
	return nil
}

func TestExecutionHandler_ListExecutions(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "output_a", "")
	store.Create(e1)

	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkFailed("error_b", 1)
	store.Create(e2)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_FilterByState(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "out", "")
	store.Create(e1)

	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkFailed("err", 1)
	store.Create(e2)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?state=failed", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_FilterByContinuation(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_a", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := execution.NewExecution("cnt_a", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e3 := execution.NewExecution("cnt_b", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?continuation_id=cnt_a", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_FilterByDecision(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_1", "dec_abc", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := execution.NewExecution("cnt_2", "dec_abc", "apr_2", "agt_2", "exec", "exec:ls", 60)
	e3 := execution.NewExecution("cnt_3", "dec_xyz", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?decision_id=dec_abc", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_FilterByActionType(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "exec", "exec:ls", 60)
	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?action_type=exec", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_FilterByStateAndActionType(t *testing.T) {
	store := execution.NewInMemoryStore()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "out", "")
	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "exec", "exec:ls", 60)
	e2.MarkSucceeded(0, "out", "")
	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	e3.MarkFailed("err", 1)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?state=succeeded&action_type=shell", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestExecutionHandler_ListExecutions_EmptyResult(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?state=pending", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0", result["count"])
	}
	execs := result["executions"].([]any)
	if len(execs) != 0 {
		t.Errorf("executions length = %d, want 0", len(execs))
	}
}

func TestExecutionHandler_GetExecution(t *testing.T) {
	store := execution.NewInMemoryStore()
	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	e.MarkSucceeded(0, "hello", "")
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/"+e.ExecutionID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)
	exec, ok := resp["execution"].(map[string]any)
	if !ok {
		t.Fatal("execution not in response")
	}
	if exec["state"] != string(execution.StateSucceeded) {
		t.Errorf("state = %v, want succeeded", exec["state"])
	}
}

func TestExecutionHandler_GetExecution_NotFound(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions/exe_notfound", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestContinuationHandler_Execute_Success(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "hello"}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state = %s, want executed", updatedCnt.State)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Fatalf("executions count = %d, want 1", len(execs))
	}
	if execs[0].State != execution.StateSucceeded {
		t.Errorf("execution state = %s, want succeeded", execs[0].State)
	}

	execEvents := eventStore.List(10)
	found := false
	for _, e := range execEvents {
		if e.EventType == eventsstore.EventTypeExecutionSucceeded {
			found = true
			break
		}
	}
	if !found {
		t.Error("execution.succeeded event not found")
	}
}

func TestContinuationHandler_Execute_Truncation(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:printf 'X%.0s' {1..100}")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	realExec := execution.NewShellExecutorWithLimits(10, 20, 1024*1024)
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(realExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Fatalf("executions count = %d, want 1", len(execs))
	}
	if execs[0].State != execution.StateSucceeded {
		t.Errorf("state = %s, want succeeded", execs[0].State)
	}
	if !execs[0].StdoutTruncated {
		t.Error("stdout_truncated = false, want true")
	}
	if len(execs[0].Stdout) > 20 {
		t.Errorf("stdout len = %d, want <= 20", len(execs[0].Stdout))
	}
	if execs[0].StdoutLimitBytes != 20 {
		t.Errorf("stdout_limit_bytes = %d, want 20", execs[0].StdoutLimitBytes)
	}
}

func TestContinuationHandler_Execute_TimedOut(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:sleep 10")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateTimedOut}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute?timeout_seconds=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state after timeout = %s, want executed (timed out → executed for retry)", updatedCnt.State)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Fatalf("executions count = %d, want 1", len(execs))
	}
	if execs[0].State != execution.StateTimedOut {
		t.Errorf("execution state = %s, want timed_out", execs[0].State)
	}

	execEvents := eventStore.List(10)
	found := false
	eventType := ""
	for _, e := range execEvents {
		if strings.Contains(e.EventType, "execution") {
			found = true
			eventType = e.EventType
			break
		}
	}
	if !found {
		t.Error("no execution event found")
	}
	if eventType != eventsstore.EventTypeExecutionTimedOut {
		t.Errorf("event type = %s, want execution.timed_out", eventType)
	}
}

func TestContinuationHandler_Execute_Failed(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:exit 1")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateFailed, resultErr: "exit status 1"}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state after failure = %s, want executed (failed → executed for retry)", updatedCnt.State)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Fatalf("executions count = %d, want 1", len(execs))
	}
	if execs[0].State != execution.StateFailed {
		t.Errorf("execution state = %s, want failed", execs[0].State)
	}

	execEvents := eventStore.List(10)
	found := false
	eventType := ""
	for _, e := range execEvents {
		if strings.Contains(e.EventType, "execution") {
			found = true
			eventType = e.EventType
			break
		}
	}
	if !found {
		t.Error("no execution event found")
	}
	if eventType != eventsstore.EventTypeExecutionFailed {
		t.Errorf("event type = %s, want execution.failed", eventType)
	}
}

func TestContinuationHandler_Execute_DuplicateBlocked(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	cnt.State = continuation.StateResumed
	cnt.MarkExecuted()
	contStore.Create(cnt)

	exec1 := execution.NewExecution(cnt.ContinuationID, cnt.DecisionID, cnt.ApprovalID, cnt.AgentID, "shell", "shell:echo hello", 60)
	exec1.MarkSucceeded(0, "hello", "")
	execStore.Create(exec1)
	cnt.MarkExecuted()
	contStore.Update(cnt)

	mockExec := &mockExecutor{}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 for duplicate execution", rec.Code)
	}

	if mockExec.called > 0 {
		t.Errorf("executor called %d times, want 0 for blocked duplicate", mockExec.called)
	}
}

func TestContinuationHandler_Execute_NonShellBlocked(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "git.push", "git:acme/repo")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for non-shell action type", rec.Code)
	}
}

func TestContinuationHandler_Execute_AlreadyExecutedBlocked(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.State = continuation.StateExecuted
	contStore.Create(cnt)

	mockExec := &mockExecutor{}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 for already-executed continuation", rec.Code)
	}
}

func TestContinuationHandler_Execute_ApprovedAutoReady(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "hello"}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (approved should auto-transition to ready)", rec.Code)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Errorf("executions count = %d, want 1", len(execs))
	}
}

func TestContinuationHandler_Execute_ExecActionType_Success(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_exec_1", "exec", "exec:ls")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "file1\nfile2"}
	reg := execution.NewExecutorRegistry()
	reg.Register("exec", mockExec)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutorRegistry(reg)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state = %s, want executed", updatedCnt.State)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Fatalf("executions count = %d, want 1", len(execs))
	}
	if execs[0].State != execution.StateSucceeded {
		t.Errorf("execution state = %s, want succeeded", execs[0].State)
	}
	if execs[0].ActionType != "exec" {
		t.Errorf("execution action_type = %s, want exec", execs[0].ActionType)
	}
	if execs[0].Stdout != "file1\nfile2" {
		t.Errorf("execution stdout = %q, want %q", execs[0].Stdout, "file1\nfile2")
	}
}

func TestContinuationHandler_Execute_ExecActionType_NoExecutor(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_exec_2", "exec", "exec:ls")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	reg := execution.NewExecutorRegistry()
	reg.Register("shell", &mockExecutor{})

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutorRegistry(reg)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no executor for exec)", rec.Code)
	}
}

func TestContinuationHandler_Execute_ResumedExecutable(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.State = continuation.StateResumed
	contStore.Create(cnt)

	mockExec := &mockExecutor{}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for resumed continuation (bug fix: resumed continuations are now executable)", rec.Code)
	}

	execs := execStore.ListAll()
	if len(execs) != 1 {
		t.Errorf("executions count = %d, want 1", len(execs))
	}
}

func TestContinuationHandler_Execute_TimeoutWithCorrectEvent(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:sleep 5")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	mockExec := &mockExecutor{resultState: execution.StateTimedOut}
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(mockExec)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute?timeout_seconds=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["state"] != "timed_out" {
		t.Errorf("response state = %v, want timed_out", resp["state"])
	}

	execs := execStore.ListByState(execution.StateTimedOut)
	if len(execs) != 1 {
		t.Errorf("timed_out executions count = %d, want 1", len(execs))
	}
}

func TestContinuationHandler_RetryAfterTimeout(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:sleep 5")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	firstExec := execution.NewExecution(cnt.ContinuationID, cnt.DecisionID, cnt.ApprovalID, cnt.AgentID, "shell", "shell:sleep 5", 1)
	firstExec.MarkTimedOut()
	execStore.Create(firstExec)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "fast command"})
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute?timeout_seconds=5", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (retry after timeout should succeed)", rec.Code)
	}

	execs := execStore.ListByContinuation(cnt.ContinuationID)
	if len(execs) != 2 {
		t.Errorf("executions count after retry = %d, want 2", len(execs))
	}

	var timedOut, succeeded int
	for _, e := range execs {
		if e.State == execution.StateTimedOut {
			timedOut++
		}
		if e.State == execution.StateSucceeded {
			succeeded++
		}
	}
	if timedOut != 1 {
		t.Errorf("timed_out executions = %d, want 1", timedOut)
	}
	if succeeded != 1 {
		t.Errorf("succeeded executions = %d, want 1", succeeded)
	}

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state after successful retry = %s, want executed", updatedCnt.State)
	}
}

func TestContinuationHandler_Execute_NotFound(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cnt_nonexistent/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestContinuationHandler_Execute_MethodNotAllowed(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	cnt := continuation.NewContinuation("dec_1", "shell", "shell:echo hello")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	h := NewContinuationHandler(contStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestExecution_RetryAfterNonZeroExit(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:exit 1")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{resultState: execution.StateFailed, resultErr: "exit status 1"})
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("continuation state after non-zero exit = %s, want executed", updatedCnt.State)
	}

	retryReq := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/retry", nil)
	retryRec := httptest.NewRecorder()
	mux.ServeHTTP(retryRec, retryReq)

	if retryRec.Code != http.StatusAccepted {
		t.Errorf("retry after non-zero exit: status = %d, want 202", retryRec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("retry execute after non-zero exit: status = %d, want 200", rec2.Code)
	}

	execs := execStore.ListByContinuation(cnt.ContinuationID)
	if len(execs) != 2 {
		t.Errorf("executions after retry = %d, want 2", len(execs))
	}
}

func TestExecution_FileBackedStore_ReloadSurvivesRestart(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/executions.jsonl"

	{
		store, err := execution.NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("first store creation failed: %v", err)
		}

		e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
		e1.MarkSucceeded(0, "output_a", "")
		store.Create(e1)

		e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:exit 1", 60)
		e2.MarkFailed("exit status 1", 1)
		store.Create(e2)

		e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:sleep 10", 60)
		e3.MarkTimedOut()
		store.Create(e3)

		store.Close()
	}

	{
		store, err := execution.NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("reload store creation failed: %v", err)
		}
		defer store.Close()

		execs := store.ListAll()
		if len(execs) != 3 {
			t.Fatalf("reloaded executions count = %d, want 3", len(execs))
		}

		succeeded := store.ListByState(execution.StateSucceeded)
		if len(succeeded) != 1 {
			t.Errorf("reloaded succeeded count = %d, want 1", len(succeeded))
		}

		failed := store.ListByState(execution.StateFailed)
		if len(failed) != 1 {
			t.Errorf("reloaded failed count = %d, want 1", len(failed))
		}

		timedOut := store.ListByState(execution.StateTimedOut)
		if len(timedOut) != 1 {
			t.Errorf("reloaded timed_out count = %d, want 1", len(timedOut))
		}

		total, succeededCnt, failedCnt, running, timedOutCnt := store.Stats()
		if total != 3 {
			t.Errorf("stats.total = %d, want 3", total)
		}
		if succeededCnt != 1 {
			t.Errorf("stats.succeeded = %d, want 1", succeededCnt)
		}
		if failedCnt != 1 {
			t.Errorf("stats.failed = %d, want 1", failedCnt)
		}
		if timedOutCnt != 1 {
			t.Errorf("stats.timedOut = %d, want 1", timedOutCnt)
		}
		if running != 0 {
			t.Errorf("stats.running = %d, want 0", running)
		}
	}
}

func TestExecution_FileBackedStore_ReloadStatePreservesTimestamps(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/executions.jsonl"

	{
		store, err := execution.NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("store creation failed: %v", err)
		}

		e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
		e.MarkStarted()
		e.MarkSucceeded(0, "hello world", "")

		store.Create(e)
		store.Close()
	}

	{
		store, err := execution.NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("reload failed: %v", err)
		}
		defer store.Close()

		execs := store.ListAll()
		if len(execs) != 1 {
			t.Fatalf("reloaded count = %d, want 1", len(execs))
		}

		reloaded := execs[0]
		if reloaded.State != execution.StateSucceeded {
			t.Errorf("reloaded state = %s, want succeeded", reloaded.State)
		}
		if reloaded.Stdout != "hello world" {
			t.Errorf("reloaded stdout = %s, want 'hello world'", reloaded.Stdout)
		}
		if reloaded.StartedAt.IsZero() {
			t.Error("reloaded started_at is zero")
		}
		if reloaded.FinishedAt == nil {
			t.Error("reloaded finished_at is nil")
		}
		if reloaded.ExitCode != 0 {
			t.Errorf("reloaded exit_code = %d, want 0", reloaded.ExitCode)
		}
	}
}

func TestExecution_Stats_FiveValues(t *testing.T) {
	store := execution.NewInMemoryStore()

	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	e4 := execution.NewExecution("cnt_4", "dec_4", "apr_4", "agt_4", "shell", "shell:echo d", 60)
	e5 := execution.NewExecution("cnt_5", "dec_5", "apr_5", "agt_5", "shell", "shell:echo e", 60)

	store.Create(e1)
	store.Create(e2)
	store.Create(e3)
	store.Create(e4)
	store.Create(e5)

	e1.MarkSucceeded(0, "", "")
	e2.MarkFailed("err", 1)
	e3.MarkStarted()
	e4.MarkTimedOut()

	store.Update(e1)
	store.Update(e2)
	store.Update(e3)
	store.Update(e4)

	total, succeeded, failed, running, timedOut := store.Stats()
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if succeeded != 1 {
		t.Errorf("succeeded = %d, want 1", succeeded)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if running != 1 {
		t.Errorf("running = %d, want 1", running)
	}
	if timedOut != 1 {
		t.Errorf("timedOut = %d, want 1", timedOut)
	}
}

func TestContinuation_CanExecute_Semantics(t *testing.T) {
	tests := []struct {
		name     string
		state    continuation.State
		action   string
		expected bool
	}{
		{"ready_shell", continuation.StateQueued, "shell", true},
		{"approved_shell", continuation.StateApproved, "shell", true},
		{"executed_shell", continuation.StateExecuted, "shell", false},
		{"resumed_shell", continuation.StateResumed, "shell", true},
		{"denied_shell", continuation.StateDenied, "shell", false},
		{"expired_shell", continuation.StateExpired, "shell", false},
		{"queued_non_shell", continuation.StateQueued, "git.push", true},
		{"escalated_shell", continuation.StateEscalated, "shell", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := continuation.NewContinuation("dec_1", tt.action, "shell:echo hi")
			c.State = tt.state
			if c.CanExecute() != tt.expected {
				t.Errorf("CanExecute() for state=%s action=%s = %v, want %v",
					c.State, tt.action, c.CanExecute(), tt.expected)
			}
		})
	}
}

func TestContinuation_RetrySemantics_AfterTimeout(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:sleep 10")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	e := execution.NewExecution(cnt.ContinuationID, cnt.DecisionID, cnt.ApprovalID, cnt.AgentID, "shell", "shell:sleep 10", 1)
	e.MarkTimedOut()
	execStore.Create(e)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "ok"})
	h.SetEventStore(eventsstore.NewInMemoryStore(1000))
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("after timeout retry, continuation state = %s, want executed", updatedCnt.State)
	}

	newExecs := execStore.ListByContinuation(cnt.ContinuationID)
	if len(newExecs) != 2 {
		t.Errorf("executions after retry = %d, want 2", len(newExecs))
	}
}

func TestContinuation_RetrySemantics_AfterNonZeroExit(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_1", "shell", "shell:exit 1")
	cnt.MarkApproved("admin")
	contStore.Create(cnt)

	e := execution.NewExecution(cnt.ContinuationID, cnt.DecisionID, cnt.ApprovalID, cnt.AgentID, "shell", "shell:exit 1", 60)
	e.MarkFailed("exit status 1", 1)
	execStore.Create(e)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{resultState: execution.StateSucceeded, resultExit: 0, resultOutput: "retry succeeded"})
	h.SetEventStore(eventsstore.NewInMemoryStore(1000))
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	updatedCnt, _ := contStore.Get(cnt.ContinuationID)
	if updatedCnt.State != continuation.StateExecuted {
		t.Errorf("after failure retry, continuation state = %s, want executed", updatedCnt.State)
	}
}

func TestContinuation_IsExecutable_ExcludesExecuted(t *testing.T) {
	c := continuation.NewContinuation("dec_1", "shell", "shell:echo hi")
	c.State = continuation.StateExecuted

	if c.IsExecutable() {
		t.Error("IsExecutable() for executed = true, want false")
	}
}

func TestContinuation_IsExecutable_ExcludesDenied(t *testing.T) {
	c := continuation.NewContinuation("dec_1", "shell", "shell:echo hi")
	c.State = continuation.StateDenied

	if c.IsExecutable() {
		t.Error("IsExecutable() for denied = true, want false")
	}
}

func TestContinuation_IsExecutable_ExcludesExpired(t *testing.T) {
	c := continuation.NewContinuation("dec_1", "shell", "shell:echo hi")
	c.State = continuation.StateExpired

	if c.IsExecutable() {
		t.Error("IsExecutable() for expired = true, want false")
	}
}
func TestContinuationHandler_RecoverExecuting_Empty(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["scanned"].(float64) != 0 {
		t.Errorf("scanned = %v, want 0", result["scanned"])
	}
	if result["recovered"].(float64) != 0 {
		t.Errorf("recovered = %v, want 0", result["recovered"])
	}
}

func TestContinuationHandler_RecoverExecuting_RecoversStuck(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	// Create stuck continuations
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.MaxRetries = 3
	contStore.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuting
	c2.MaxRetries = 3
	contStore.Create(c2)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["scanned"].(float64) != 2 {
		t.Errorf("scanned = %v, want 2", result["scanned"])
	}
	if result["recovered"].(float64) != 2 {
		t.Errorf("recovered = %v, want 2", result["recovered"])
	}

	// Verify state in store
	updated1, _ := contStore.Get(c1.ContinuationID)
	if updated1.State != continuation.StateExecuted {
		t.Errorf("c1 state after recovery = %v, want executed", updated1.State)
	}
	if !updated1.CanRetry() {
		t.Error("c1 should be retryable after recovery")
	}

	// Verify event was emitted
	if eventStore.Count() == 0 {
		t.Error("expected at least one event to be emitted")
	}
}

func TestContinuationHandler_RecoverExecuting_DryRun(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.MaxRetries = 3
	contStore.Create(c1)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing?dry_run=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["dry_run"] != true {
		t.Error("dry_run should be true in response")
	}
	if result["scanned"].(float64) != 1 {
		t.Errorf("scanned = %v, want 1", result["scanned"])
	}
	if result["recovered"].(float64) != 0 {
		t.Errorf("recovered = %v, want 0 in dry run", result["recovered"])
	}

	// Verify state was NOT changed
	updated1, _ := contStore.Get(c1.ContinuationID)
	if updated1.State != continuation.StateExecuting {
		t.Errorf("c1 state = %v, want executing (dry run should not mutate)", updated1.State)
	}
}

func TestContinuationHandler_RecoverExecuting_SkipsNonExecuting(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	// Stuck continuation
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	contStore.Create(c1)

	// Non-executing continuation (should be skipped, not in scanned list)
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.MarkApproved("admin")
	contStore.Create(c2)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	if result["scanned"].(float64) != 1 {
		t.Errorf("scanned = %v, want 1 (only executing continuations are scanned)", result["scanned"])
	}
	if result["recovered"].(float64) != 1 {
		t.Errorf("recovered = %v, want 1", result["recovered"])
	}
}

func TestContinuationHandler_RecoverExecuting_OlderThanMinutes_FiltersYoung(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.MaxRetries = 3
	contStore.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuting
	c2.MaxRetries = 3
	contStore.Create(c2)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing?older_than_minutes=10", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["scanned"].(float64) != 2 {
		t.Errorf("scanned = %v, want 2 (all items scanned)", result["scanned"])
	}
	if result["recovered"].(float64) != 0 {
		t.Errorf("recovered = %v, want 0 (items are too young)", result["recovered"])
	}
	if result["skipped"].(float64) != 2 {
		t.Errorf("skipped = %v, want 2 (both filtered by age)", result["skipped"])
	}
}

func TestContinuationHandler_RecoverExecuting_OlderThanMinutes_RecoversOld(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.MaxRetries = 3
	c1.CreatedAt = time.Now().UTC().Add(-20 * time.Minute)
	contStore.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuting
	c2.MaxRetries = 3
	c2.CreatedAt = time.Now().UTC().Add(-5 * time.Minute)
	contStore.Create(c2)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/recover-executing?older_than_minutes=10", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["scanned"].(float64) != 2 {
		t.Errorf("scanned = %v, want 2", result["scanned"])
	}
	if result["recovered"].(float64) != 1 {
		t.Errorf("recovered = %v, want 1 (only c1 is older than 10 min)", result["recovered"])
	}
	if result["skipped"].(float64) != 1 {
		t.Errorf("skipped = %v, want 1 (c2 is too young)", result["skipped"])
	}

	updated1, _ := contStore.Get(c1.ContinuationID)
	if updated1.State != continuation.StateExecuted {
		t.Errorf("c1 state after recovery = %v, want executed", updated1.State)
	}
	updated2, _ := contStore.Get(c2.ContinuationID)
	if updated2.State != continuation.StateExecuting {
		t.Errorf("c2 state should still be executing, got %v", updated2.State)
	}
}

func TestContinuationHandler_RecoverExecutingItem_Success(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.MaxRetries = 3
	contStore.Create(c1)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c1.ContinuationID+"/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["continuation_id"] != c1.ContinuationID {
		t.Errorf("continuation_id = %v, want %v", result["continuation_id"], c1.ContinuationID)
	}
	if result["state"] != "executed" {
		t.Errorf("state = %v, want executed", result["state"])
	}

	updated, _ := contStore.Get(c1.ContinuationID)
	if updated.State != continuation.StateExecuted {
		t.Errorf("store state = %v, want executed", updated.State)
	}
	if !updated.CanRetry() {
		t.Error("continuation should be retryable after recovery")
	}
}

func TestContinuationHandler_RecoverExecutingItem_NotFound(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cnt_notfound/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestContinuationHandler_RecoverExecutingItem_WrongState(t *testing.T) {
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	eventStore := eventsstore.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.MarkApproved("admin")
	contStore.Create(c1)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c1.ContinuationID+"/recover-executing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}

	updated, _ := contStore.Get(c1.ContinuationID)
	if updated.State != continuation.StateApproved {
		t.Errorf("state should be unchanged, got %v", updated.State)
	}
}

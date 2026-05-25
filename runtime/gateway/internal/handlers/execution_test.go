package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	var result execution.Execution
	json.NewDecoder(rec.Body).Decode(&result)
	if result.State != execution.StateSucceeded {
		t.Errorf("state = %s, want succeeded", result.State)
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
	if updatedCnt.State != continuation.StateReady {
		t.Errorf("continuation state after timeout = %s, want ready", updatedCnt.State)
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
	if updatedCnt.State != continuation.StateReady {
		t.Errorf("continuation state after failure = %s, want ready (for retry)", updatedCnt.State)
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
	cnt.MarkReady()
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

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for duplicate execution", rec.Code)
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

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for already-executed continuation", rec.Code)
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
	if updatedCnt.State != continuation.StateReady {
		t.Errorf("continuation state after non-zero exit = %s, want ready", updatedCnt.State)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("retry after non-zero exit: status = %d, want 200", rec2.Code)
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
		{"ready_shell", continuation.StateReady, "shell", true},
		{"approved_shell", continuation.StateApproved, "shell", false},
		{"executed_shell", continuation.StateExecuted, "shell", false},
		{"resumed_shell", continuation.StateResumed, "shell", true},
		{"denied_shell", continuation.StateDenied, "shell", false},
		{"expired_shell", continuation.StateExpired, "shell", false},
		{"ready_non_shell", continuation.StateReady, "git.push", false},
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
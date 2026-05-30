package handlers

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
	eventsstore "ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

func TestInMemoryStore_ClaimForExecution_RaceProof_OnlyOneWins(t *testing.T) {
	store := continuation.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_race2", "shell", "shell:sleep 1")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	var won int32
	var lost int32
	const n = 10

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, claimed := store.ClaimForExecution(cnt.ContinuationID)
			if claimed {
				atomic.AddInt32(&won, 1)
			} else {
				atomic.AddInt32(&lost, 1)
			}
		}()
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("exactly one ClaimForExecution should win, got won=%d lost=%d", won, lost)
	}
	if lost != n-1 {
		t.Errorf("all other claims should lose, got won=%d lost=%d", won, lost)
	}
}

func TestInMemoryStore_ClaimForRetry_RaceProof_OnlyOneWins(t *testing.T) {
	store := continuation.NewInMemoryStore()

	cnt := continuation.NewContinuation("dec_retry_race", "shell", "shell:ls")
	cnt.State = continuation.StateResumed
	cnt.RetryCount = 1
	cnt.MaxRetries = 5
	store.Create(cnt)

	var won int32
	var lost int32
	const n = 10

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, claimed := store.ClaimForRetry(cnt.ContinuationID)
			if claimed {
				atomic.AddInt32(&won, 1)
			} else {
				atomic.AddInt32(&lost, 1)
			}
		}()
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("exactly one ClaimForRetry should win, got won=%d lost=%d", won, lost)
	}
	if lost != n-1 {
		t.Errorf("all other claims should lose, got won=%d lost=%d", won, lost)
	}
}

func TestContinuationHandler_Execute_StateApproved_TransitionsToReady(t *testing.T) {
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
		t.Errorf("executions count = %d, want 1", len(execs))
	}
}

func TestContinuationHandler_Execute_ClaimForExecution_QueuedRejected(t *testing.T) {
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
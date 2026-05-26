package continuation

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/execution"
)

type mockExecutor struct {
	calls int32
}

func (m *mockExecutor) Execute(ctx context.Context, e *execution.Execution) error {
	atomic.AddInt32(&m.calls, 1)
	e.MarkStarted()
	e.MarkSucceeded(0, "ok", "")
	return nil
}

func (m *mockExecutor) Calls() int {
	return int(atomic.LoadInt32(&m.calls))
}

type mockExecStore struct {
	executions []*execution.Execution
}

func (m *mockExecStore) Create(e *execution.Execution) error {
	m.executions = append(m.executions, e)
	return nil
}

func (m *mockExecStore) Get(id string) (*execution.Execution, bool) {
	for _, e := range m.executions {
		if e.ExecutionID == id {
			return e, true
		}
	}
	return nil, false
}

func (m *mockExecStore) Update(e *execution.Execution) error {
	for i, ex := range m.executions {
		if ex.ExecutionID == e.ExecutionID {
			m.executions[i] = e
			return nil
		}
	}
	m.executions = append(m.executions, e)
	return nil
}

func (m *mockExecStore) ListAll() []*execution.Execution { return m.executions }
func (m *mockExecStore) ListByState(state execution.State) []*execution.Execution {
	var r []*execution.Execution
	for _, e := range m.executions {
		if e.State == state {
			r = append(r, e)
		}
	}
	return r
}
func (m *mockExecStore) ListByContinuation(contID string) []*execution.Execution { return nil }
func (m *mockExecStore) ListByDecision(decisionID string) []*execution.Execution { return nil }
func (m *mockExecStore) Stats() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (m *mockExecStore) Close() error { return nil }

func TestOrchestrator_PicksUpQueuedContinuation(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 100 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_1", "shell", "shell:ls")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	time.Sleep(400 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateExecuted {
		t.Errorf("continuation state = %v, want executed", updated.State)
	}
	if exec.Calls() == 0 {
		t.Error("expected executor to be called at least once")
	}
	if len(execStore.executions) == 0 {
		t.Error("expected at least one execution record")
	}
}

func TestOrchestrator_PausesExecution(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 50 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_pause", "shell", "shell:sleep 10")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	orch.Pause()
	time.Sleep(150 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateQueued {
		t.Errorf("continuation state = %v, want queued (paused)", updated.State)
	}
	if exec.Calls() != 0 {
		t.Errorf("executor calls = %d, want 0 when paused", exec.Calls())
	}

	orch.Resume()
	time.Sleep(200 * time.Millisecond)

	updated, _ = store.Get(cnt.ContinuationID)
	if updated.State != StateExecuted {
		t.Errorf("continuation state after resume = %v, want executed", updated.State)
	}
}

func TestOrchestrator_DoesNotRePickExecuted(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 50 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_once", "shell", "shell:ls")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	time.Sleep(300 * time.Millisecond)

	if exec.Calls() != 1 {
		t.Errorf("executor calls = %d, want 1", exec.Calls())
	}
}

func TestOrchestrator_RespectsExpiryTimeout(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 50 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	expiresSoon := time.Now().Add(3 * time.Second)
	cnt := NewContinuation("dec_expiry", "shell", "shell:ls")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	cnt.ExpiresAt = &expiresSoon
	store.Create(cnt)

	time.Sleep(200 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateExecuted {
		t.Errorf("continuation state = %v, want executed", updated.State)
	}
}

func TestOrchestrator_QueueStats(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 100 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	c1 := NewContinuation("dec_q1", "shell", "shell:ls")
	c1.MarkApproved("admin")
	c1.MarkQueued()
	store.Create(c1)

	c2 := NewContinuation("dec_q2", "shell", "shell:pwd")
	c2.MarkApproved("admin")
	c2.MarkQueued()
	store.Create(c2)

	time.Sleep(50 * time.Millisecond)
	queued, running := orch.QueueStats()
	if queued != 2 {
		t.Errorf("queued = %d, want 2", queued)
	}
	_ = running
}

func TestOrchestrator_CancelBeforeExecution(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}

	orch := NewOrchestrator(store, execStore, exec)
	orch.pollInterval = 500 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_cancel", "shell", "shell:sleep 30")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	time.Sleep(50 * time.Millisecond)

	orch.Pause()
	cnt.MarkCancelled()
	store.Update(cnt)

	time.Sleep(600 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateCancelled {
		t.Errorf("continuation state = %v, want cancelled", updated.State)
	}
}

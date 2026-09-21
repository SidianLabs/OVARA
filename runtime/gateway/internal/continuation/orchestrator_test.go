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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
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

func TestOrchestrator_PicksUpExecContinuation(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("exec", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 100 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_exec_1", "exec", "exec:ls")
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
	execRecord := execStore.executions[0]
	if execRecord.ActionType != "exec" {
		t.Errorf("execution action_type = %s, want exec", execRecord.ActionType)
	}
}

func TestOrchestrator_UnknownActionType_SkipsExecution(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 200 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_unknown", "git.push", "git:origin main")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	time.Sleep(500 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateQueued {
		t.Errorf("continuation state = %v, want queued (no executor registered, should not execute)", updated.State)
	}
	if exec.Calls() != 0 {
		t.Errorf("executor calls = %d, want 0 (unknown action type)", exec.Calls())
	}
}

func TestOrchestrator_StartupSweepStuckExecuting(t *testing.T) {
	store := NewInMemoryStore()

	stuck := NewContinuation("dec_stuck", "shell", "shell:sleep 10")
	stuck.State = StateExecuting
	stuck.MaxRetries = 3
	stuck.RetryCount = 0
	store.Create(stuck)

	execStore := &mockExecStore{}
	reg := execution.NewExecutorRegistry()

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 500 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	updated, _ := store.Get(stuck.ContinuationID)
	if updated.State != StateExecuted {
		t.Errorf("stuck executing should be swept to executed on startup, got %v", updated.State)
	}
	if !updated.CanRetry() {
		t.Error("swept continuation should be retryable")
	}
}

func TestOrchestrator_StartupSweepIdempotent(t *testing.T) {
	store := NewInMemoryStore()

	normal := NewContinuation("dec_normal", "shell", "shell:ls")
	normal.State = StateExecuted
	store.Create(normal)

	queued := NewContinuation("dec_queued", "shell", "shell:pwd")
	queued.MarkApproved("admin")
	queued.MarkQueued()
	store.Create(queued)

	execStore := &mockExecStore{}
	reg := execution.NewExecutorRegistry()

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 500 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	updatedNormal, _ := store.Get(normal.ContinuationID)
	if updatedNormal.State != StateExecuted {
		t.Errorf("executed continuation should be unaffected, got %v", updatedNormal.State)
	}

	updatedQueued, _ := store.Get(queued.ContinuationID)
	if updatedQueued.State != StateQueued {
		t.Errorf("queued continuation should be unaffected, got %v", updatedQueued.State)
	}
}

func TestOrchestrator_SkipNoExecutor_UsesMarkRequeue(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 200 * time.Millisecond
	orch.Start()
	defer orch.Stop()

	cnt := NewContinuation("dec_skip", "git.push", "git:origin main")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	time.Sleep(600 * time.Millisecond)

	updated, _ := store.Get(cnt.ContinuationID)
	if updated.State != StateQueued {
		t.Errorf("state after skip = %v, want queued (requeued, not stuck in executing)", updated.State)
	}
	if updated.QueuedAt == nil {
		t.Error("QueuedAt should be set after MarkRequeue")
	}
	if exec.Calls() != 0 {
		t.Errorf("executor calls = %d, want 0 (no executor for git.push)", exec.Calls())
	}
}

func TestOrchestrator_RecoverAllExecuting(t *testing.T) {
	store := NewInMemoryStore()

	c1 := NewContinuation("dec_r1", "shell", "shell:ls")
	c1.State = StateExecuting
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := NewContinuation("dec_r2", "shell", "shell:pwd")
	c2.State = StateExecuting
	c2.MaxRetries = 3
	store.Create(c2)

	c3 := NewContinuation("dec_r3", "shell", "shell:whoami")
	c3.MarkApproved("admin")
	store.Create(c3)

	execStore := &mockExecStore{}
	reg := execution.NewExecutorRegistry()

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 500 * time.Millisecond

	recovered := orch.RecoverAllExecuting()
	if recovered != 2 {
		t.Errorf("recovered = %d, want 2", recovered)
	}

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.State != StateExecuted {
		t.Errorf("c1 state = %v, want executed", updated1.State)
	}
	if !updated1.CanRetry() {
		t.Error("c1 should be retryable after recovery")
	}

	updated3, _ := store.Get(c3.ContinuationID)
	if updated3.State != StateApproved {
		t.Errorf("c3 state = %v, want approved (untouched)", updated3.State)
	}

	if orch.ExecutingCount() != 0 {
		t.Errorf("ExecutingCount after recovery = %d, want 0", orch.ExecutingCount())
	}
}

func TestOrchestrator_ExecutingCount(t *testing.T) {
	store := NewInMemoryStore()

	c1 := NewContinuation("dec_e1", "shell", "shell:ls")
	c1.State = StateExecuting
	store.Create(c1)

	c2 := NewContinuation("dec_e2", "shell", "shell:pwd")
	c2.State = StateExecuting
	store.Create(c2)

	c3 := NewContinuation("dec_e3", "shell", "shell:whoami")
	c3.MarkApproved("admin")
	store.Create(c3)

	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	if got := orch.ExecutingCount(); got != 2 {
		t.Errorf("ExecutingCount = %d, want 2", got)
	}
}

func TestOrchestrator_OldestExecutingAt(t *testing.T) {
	store := NewInMemoryStore()

	now := time.Now().UTC()
	old := now.Add(-10 * time.Minute)
	mid := now.Add(-5 * time.Minute)

	c1 := NewContinuation("dec_old", "shell", "shell:ls")
	c1.State = StateExecuting
	c1.CreatedAt = old
	store.Create(c1)

	c2 := NewContinuation("dec_mid", "shell", "shell:pwd")
	c2.State = StateExecuting
	c2.CreatedAt = mid
	store.Create(c2)

	c3 := NewContinuation("dec_other", "shell", "shell:whoami")
	c3.MarkApproved("admin")
	c3.CreatedAt = now.Add(-1 * time.Hour)
	store.Create(c3)

	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	oldest := orch.OldestExecutingAt()
	if !oldest.Equal(old) {
		t.Errorf("OldestExecutingAt = %v, want %v", oldest, old)
	}
}

func TestOrchestrator_OldestExecutingAt_Empty(t *testing.T) {
	store := NewInMemoryStore()
	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	if !orch.OldestExecutingAt().IsZero() {
		t.Error("OldestExecutingAt should be zero when no executing continuations exist")
	}
}

func TestOrchestrator_SetStuckExecutingSweep(t *testing.T) {
	store := NewInMemoryStore()
	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())

	orch.SetStuckExecutingSweep(0, 30)
	if orch.stuckSweepInterval != 0 {
		t.Errorf("interval with 0 should be disabled, got %v", orch.stuckSweepInterval)
	}

	orch.SetStuckExecutingSweep(600, 30)
	if orch.stuckSweepInterval != 10*time.Minute {
		t.Errorf("interval = %v, want 10m", orch.stuckSweepInterval)
	}
	if orch.stuckRecoveryThreshold != 30*time.Minute {
		t.Errorf("threshold = %v, want 30m", orch.stuckRecoveryThreshold)
	}

	orch.SetStuckExecutingSweep(600, 0)
	if orch.stuckRecoveryThreshold != 30*time.Minute {
		t.Errorf("threshold should default to 30m when 0, got %v", orch.stuckRecoveryThreshold)
	}
}

func TestOrchestrator_SweepStuckExecutingThreshold_RecoversOld(t *testing.T) {
	store := NewInMemoryStore()

	c1 := NewContinuation("dec_old", "shell", "shell:ls")
	c1.State = StateExecuting
	c1.MaxRetries = 3
	c1.CreatedAt = time.Now().UTC().Add(-45 * time.Minute)
	store.Create(c1)

	c2 := NewContinuation("dec_young", "shell", "shell:pwd")
	c2.State = StateExecuting
	c2.MaxRetries = 3
	c2.CreatedAt = time.Now().UTC().Add(-5 * time.Minute)
	store.Create(c2)

	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	orch.SetStuckExecutingSweep(600, 30)
	orch.sweepStuckExecutingThreshold()

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.State != StateExecuted {
		t.Errorf("old item should be recovered, got %v", updated1.State)
	}
	if !updated1.CanRetry() {
		t.Error("recovered item should be retryable")
	}

	updated2, _ := store.Get(c2.ContinuationID)
	if updated2.State != StateExecuting {
		t.Errorf("young item should NOT be recovered, got %v", updated2.State)
	}
}

func TestOrchestrator_SweepStuckExecutingThreshold_SkipsYoung(t *testing.T) {
	store := NewInMemoryStore()

	c := NewContinuation("dec_young", "shell", "shell:ls")
	c.State = StateExecuting
	c.MaxRetries = 3
	c.CreatedAt = time.Now().UTC().Add(-10 * time.Minute)
	store.Create(c)

	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	orch.SetStuckExecutingSweep(600, 30)
	orch.sweepStuckExecutingThreshold()

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != StateExecuting {
		t.Errorf("item younger than threshold should not be recovered, got %v", updated.State)
	}
}

func TestOrchestrator_SweepStuckExecutingThreshold_Disabled(t *testing.T) {
	store := NewInMemoryStore()

	c := NewContinuation("dec_old", "shell", "shell:ls")
	c.State = StateExecuting
	c.MaxRetries = 3
	c.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	store.Create(c)

	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	orch.SetStuckExecutingSweep(0, 30)
	orch.sweepStuckExecutingThreshold()

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != StateExecuting {
		t.Errorf("when disabled, nothing should be recovered, got %v", updated.State)
	}
}

func TestOrchestrator_SweepStuckExecutingThreshold_Empty(t *testing.T) {
	store := NewInMemoryStore()
	orch := NewOrchestrator(store, &mockExecStore{}, execution.NewExecutorRegistry())
	orch.SetStuckExecutingSweep(600, 30)
	orch.sweepStuckExecutingThreshold()
}

func TestOrchestrator_PeriodicSweep_RunsAndRecovers(t *testing.T) {
	store := NewInMemoryStore()

	c := NewContinuation("dec_stuck", "shell", "shell:sleep 10")
	c.State = StateExecuting
	c.MaxRetries = 3
	c.CreatedAt = time.Now().UTC().Add(-45 * time.Minute)
	store.Create(c)

	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 100 * time.Millisecond
	orch.SetStuckExecutingSweep(100, 30)
	orch.Start()
	defer orch.Stop()

	time.Sleep(250 * time.Millisecond)

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != StateExecuted {
		t.Errorf("periodic sweep should have recovered stuck item, got %v", updated.State)
	}
	if !updated.CanRetry() {
		t.Error("recovered item should be retryable")
	}
}

// panickingExecutor panics in Execute to simulate an executor crash.
type panickingExecutor struct{}

func (m *panickingExecutor) Execute(ctx context.Context, e *execution.Execution) error {
	panic("simulated executor crash")
}

func TestOrchestrator_ExecutorPanic_RecoversAndMarksFailed(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", &panickingExecutor{})

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 100 * time.Millisecond

	cnt := NewContinuation("dec_1", "shell", "shell:ls")
	cnt.MarkApproved("admin")
	cnt.MarkQueued()
	store.Create(cnt)

	// Call executeOne directly since we cannot easily observe recover()
	// inside a goroutine without races. The deferred recover handles the
	// panic internally and marks the execution as failed.
	orch.executeOne(cnt)

	updated, _ := store.Get(cnt.ContinuationID)

	// The continuation should be in StateExecuted (retryable) after panic recovery.
	if updated.State != StateExecuted {
		t.Errorf("after executor panic: state = %s, want executed (should be retryable)", updated.State)
	}
	if !updated.CanRetry() {
		t.Errorf("after executor panic: can_retry = false, want true (should be retryable)")
	}

	// The execution record should exist and be in StateFailed.
	if len(execStore.executions) == 0 {
		t.Fatal("expected an execution record after panic")
	}
	exe := execStore.executions[0]
	if exe.State != execution.StateFailed {
		t.Errorf("execution state after panic = %s, want failed", exe.State)
	}
	if exe.Error == "" {
		t.Error("execution error should be set after panic")
	}
}

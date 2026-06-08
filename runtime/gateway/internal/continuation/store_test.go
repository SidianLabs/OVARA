package continuation

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewContinuation(t *testing.T) {
	c := NewContinuation("dec_123", "shell", "shell:echo test")
	if c.ContinuationID == "" {
		t.Error("continuation_id should not be empty")
	}
	if c.DecisionID != "dec_123" {
		t.Errorf("decision_id = %s, want dec_123", c.DecisionID)
	}
	if c.State != StateEscalated {
		t.Errorf("state = %s, want escalated", c.State)
	}
	if c.CreatedAt.IsZero() {
		t.Error("created_at should not be zero")
	}
}

func TestContinuation_CanResume(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	if c.CanResume() {
		t.Error("escalated continuation should not be directly resumable - must be approved first")
	}

	c.MarkApproved("resolver1")
	if !c.CanResume() {
		t.Error("approved continuation should be resumable")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkDenied("resolver2", "too risky")
	if c2.CanResume() {
		t.Error("denied continuation should not be resumable")
	}

	c3 := NewContinuation("dec_3", "shell", "shell:ls")
	c3.MarkExpired()
	if c3.CanResume() {
		t.Error("expired continuation should not be resumable")
	}
}

func TestContinuation_IsTerminal(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	if c.IsTerminal() {
		t.Error("escalated should not be terminal")
	}

	c.MarkDenied("r", "test")
	if !c.IsTerminal() {
		t.Error("denied should be terminal")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkApproved("admin")
	c2.MarkReady()
	c2.MarkResumed()
	if c2.IsTerminal() {
		t.Error("resumed should NOT be terminal (it is a retry intermediate state)")
	}
}

func TestContinuation_MarkApproved(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")

	if c.State != StateApproved {
		t.Errorf("state = %s, want approved", c.State)
	}
	if c.ResolvedBy != "admin" {
		t.Errorf("resolved_by = %s, want admin", c.ResolvedBy)
	}
	if c.ApprovedAt == nil {
		t.Error("approved_at should be set")
	}
	if c.ApprovedAt.Location() != time.UTC {
		t.Error("approved_at should be UTC")
	}
}

func TestContinuation_IsExecutable(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	if c.IsExecutable() {
		t.Error("escalated should not be executable")
	}

	c.MarkApproved("admin")
	if !c.IsExecutable() {
		t.Error("approved should be executable")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkApproved("admin")
	c2.MarkReady()
	if !c2.IsExecutable() {
		t.Error("ready should be executable")
	}

	c3 := NewContinuation("dec_3", "shell", "shell:ls").WithExpiration(1)
	c3.MarkApproved("admin")
	c3.MarkReady()
	c3.State = StateEscalated
	if c3.IsExecutable() {
		t.Error("escalated should not be executable even if was previously approved/ready")
	}

	c4 := NewContinuation("dec_4", "shell", "shell:ls")
	c4.MarkDenied("admin", "test")
	if c4.IsExecutable() {
		t.Error("denied should not be executable")
	}
}

func TestContinuation_ShouldExpire(t *testing.T) {
	now := time.Now().UTC()

	past := now.Add(-1 * time.Hour)
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.ExpiresAt = &past
	c.State = StateApproved

	if !c.ShouldExpire(now) {
		t.Error("approved with past expiration should expire")
	}

	future := now.Add(1 * time.Hour)
	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.ExpiresAt = &future
	c2.State = StateApproved

	if c2.ShouldExpire(now) {
		t.Error("approved with future expiration should not expire")
	}

	c3 := NewContinuation("dec_3", "shell", "shell:ls")
	c3.ExpiresAt = &past
	c3.State = StateResumed

	if c3.ShouldExpire(now) {
		t.Error("resumed should not be subject to expiration check")
	}
}

func TestContinuation_MarkReady(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkReady()

	if c.State != StateReady {
		t.Errorf("state = %s, want ready", c.State)
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkReady()
	if c2.State != StateEscalated {
		t.Error("escalated continuation should not transition via MarkReady")
	}
}

func TestContinuation_MarkExpired(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkExpired()

	if c.State != StateExpired {
		t.Errorf("state = %s, want expired", c.State)
	}
	if c.ExpiredAt == nil {
		t.Error("expired_at should be set")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkDenied("admin", "test")
	c2.MarkExpired()
	if c2.State != StateDenied {
		t.Error("denied continuation should not transition to expired")
	}
}

func TestContinuation_WithExpiration(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls").
		WithExpiration(30)

	if c.ExpiresAt == nil {
		t.Fatal("expires_at should be set")
	}
	if c.ExpiresAt.IsZero() {
		t.Error("expires_at should not be zero")
	}

	elapsed := time.Since(c.CreatedAt)
	expected := 30 * time.Minute
	diff := c.ExpiresAt.Sub(c.CreatedAt)
	if diff != expected {
		t.Errorf("expires_at mismatch: got %v, want %v", diff, expected)
	}
	_ = elapsed
}

func TestContinuation_IsExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.ExpiresAt = &past

	if !c.IsExpired() {
		t.Error("continuation with past expiration should be expired")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	if c2.IsExpired() {
		t.Error("continuation with no expiration should not be expired")
	}
}

func TestContinuation_TimeToExpiry(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(60 * time.Minute)
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.ExpiresAt = &future

	ttl := c.TimeToExpiry()
	if ttl <= 59*time.Minute || ttl > 60*time.Minute {
		t.Errorf("time to expiry out of range: %v", ttl)
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	if c2.TimeToExpiry() != -1 {
		t.Error("continuation with no expiration should return -1")
	}
}

func TestContinuation_StateTransitionFlow(t *testing.T) {
	c := NewContinuation("dec_flow", "shell", "shell:ls")

	if c.State != StateEscalated {
		t.Fatalf("initial state should be escalated, got %s", c.State)
	}

	c.MarkApproved("admin")
	if c.State != StateApproved {
		t.Fatalf("after approve: state should be approved, got %s", c.State)
	}

	c.MarkReady()
	if c.State != StateReady {
		t.Fatalf("after mark ready: state should be ready, got %s", c.State)
	}

	c.MarkResumed()
	if c.State != StateResumed {
		t.Fatalf("after resume: state should be resumed, got %s", c.State)
	}
	if c.IsTerminal() {
		t.Error("resumed should NOT be terminal (it is a retry intermediate state)")
	}
}

func TestContinuation_BuilderChaining(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls").
		WithAgentID("agt_123").
		WithEnvironment("production").
		WithTrustContext(0.75, "medium", []string{"risky_shell_pattern"}, true, false).
		WithPolicyVersion("v1-prod")

	if c.AgentID != "agt_123" {
		t.Errorf("agent_id = %s, want agt_123", c.AgentID)
	}
	if c.Environment != "production" {
		t.Errorf("environment = %s, want production", c.Environment)
	}
	if c.TrustScore != 0.75 {
		t.Errorf("trust_score = %f, want 0.75", c.TrustScore)
	}
	if c.TrustLevel != "medium" {
		t.Errorf("trust_level = %s, want medium", c.TrustLevel)
	}
	if c.PolicyVersion != "v1-prod" {
		t.Errorf("policy_version = %s, want v1-prod", c.PolicyVersion)
	}
}

func TestInMemoryStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")

	err := store.Create(c)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	found, ok := store.Get(c.ContinuationID)
	if !ok {
		t.Fatal("expected to find continuation")
	}
	if found.DecisionID != "dec_1" {
		t.Errorf("decision_id = %s, want dec_1", found.DecisionID)
	}
}

func TestInMemoryStore_GetNotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, ok := store.Get("cnt_nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestInMemoryStore_Update(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_1", "shell", "shell:ls")
	store.Create(c)

	c.MarkApproved("admin")
	err := store.Update(c)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}

	found, _ := store.Get(c.ContinuationID)
	if found.State != StateApproved {
		t.Errorf("state = %s, want approved", found.State)
	}
}

func TestInMemoryStore_ListByState(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls")
	c2 := NewContinuation("dec_2", "git.push", "git:acme/repo")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	approved := store.ListByState(StateApproved)
	if len(approved) != 1 {
		t.Errorf("approved count = %d, want 1", len(approved))
	}

	escalated := store.ListByState(StateEscalated)
	if len(escalated) != 1 {
		t.Errorf("escalated count = %d, want 1", len(escalated))
	}
}

func TestInMemoryStore_ListByDecision(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls")
	c2 := NewContinuation("dec_1", "git.push", "git:acme/repo")
	store.Create(c1)
	store.Create(c2)

	list := store.ListByDecision("dec_1")
	if len(list) != 2 {
		t.Errorf("count = %d, want 2", len(list))
	}
}

func TestInMemoryStore_ListByAgent(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c2 := NewContinuation("dec_2", "shell", "shell:ls").WithAgentID("agt_b")
	c3 := NewContinuation("dec_3", "shell", "shell:ls").WithAgentID("agt_a")
	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	list := store.ListByAgent("agt_a")
	if len(list) != 2 {
		t.Errorf("count = %d, want 2", len(list))
	}
}

func TestInMemoryStore_ListAll(t *testing.T) {
	store := NewInMemoryStore()
	for i := 0; i < 3; i++ {
		c := NewContinuation("dec_"+string(rune('0'+i)), "shell", "shell:ls")
		store.Create(c)
	}

	all := store.ListAll()
	if len(all) != 3 {
		t.Errorf("count = %d, want 3", len(all))
	}
}

func TestInMemoryStore_ClaimForExecution_ClaimsExecutableContinuation(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkQueued()
	store.Create(c)

	claimed, ok := store.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("expected claim to succeed for queued continuation")
	}
	if claimed.State != StateExecuting {
		t.Errorf("state after claim = %v, want executing", claimed.State)
	}

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != StateExecuting {
		t.Errorf("state in store after claim = %v, want executing", updated.State)
	}
}

func TestInMemoryStore_ClaimForExecution_RejectsNonExecutable(t *testing.T) {
	store := NewInMemoryStore()

	c := NewContinuation("dec_escalated", "shell", "shell:ls")
	store.Create(c)
	_, ok := store.ClaimForExecution(c.ContinuationID)
	if ok {
		t.Error("expected claim to fail for escalated continuation")
	}

	c2 := NewContinuation("dec_denied", "shell", "shell:ls")
	c2.MarkDenied("admin", "risky")
	store.Create(c2)
	_, ok = store.ClaimForExecution(c2.ContinuationID)
	if ok {
		t.Error("expected claim to fail for denied continuation")
	}
}

func TestInMemoryStore_ClaimForExecution_RaceProof_OnlyOneWins(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_race", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkQueued()
	store.Create(c)

	var won int32
	var lost int32
	const n = 10

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, ok := store.ClaimForExecution(c.ContinuationID)
			if ok {
				atomic.AddInt32(&won, 1)
			} else {
				atomic.AddInt32(&lost, 1)
			}
		}()
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("exactly one claim should win, got won=%d lost=%d", won, lost)
	}
	if lost != n-1 {
		t.Errorf("all other claims should lose, got won=%d lost=%d", won, lost)
	}
}

func TestInMemoryStore_ClaimForExecution_NotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, ok := store.ClaimForExecution("cnt_nonexistent")
	if ok {
		t.Error("expected claim to fail for nonexistent id")
	}
}

func TestContinuation_StateExecuting_NotAsRestingState(t *testing.T) {
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting

	if c.IsTerminal() {
		t.Error("executing should not be terminal")
	}
	if c.IsReady() {
		t.Error("executing should not be ready")
	}
	if c.CanEnqueue() {
		t.Error("executing should not be enqueueable")
	}
	if c.CanCancel() {
		t.Error("executing should not be cancellable while running")
	}
}

func TestContinuation_MarkExecuted_FromExecuting(t *testing.T) {
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting

	c.MarkExecuted()
	if c.State != StateExecuted {
		t.Errorf("state = %v, want executed", c.State)
	}
}

func TestContinuation_MarkExecuted_RejectsNonExecuting(t *testing.T) {
	c := NewContinuation("dec_esc", "shell", "shell:ls")
	c.State = StateEscalated

	c.MarkExecuted()
	if c.State != StateEscalated {
		t.Errorf("state = %v, want escalated (unchanged)", c.State)
	}
}

func TestContinuation_MarkExecutionFailed_FromExecuting(t *testing.T) {
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting

	c.MarkExecutionFailed()
	if c.State != StateExecuted {
		t.Errorf("state = %v, want executed", c.State)
	}
}

func TestContinuation_MarkExecutionFailed_FromReady(t *testing.T) {
	c := NewContinuation("dec_ready", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkReady()

	c.MarkExecutionFailed()
	if c.State != StateExecuted {
		t.Errorf("state = %v, want executed", c.State)
	}
}

func TestContinuation_MarkExecutionFailed_RejectsNonExecuting(t *testing.T) {
	c := NewContinuation("dec_esc", "shell", "shell:ls")
	c.State = StateEscalated

	c.MarkExecutionFailed()
	if c.State != StateEscalated {
		t.Errorf("state = %v, want escalated (unchanged)", c.State)
	}
}

func TestContinuation_Retry_FromExecutedAfterMarkExecutionFailed(t *testing.T) {
	c := NewContinuation("dec_retry", "shell", "shell:ls")
	c.State = StateExecuting
	c.MaxRetries = 3
	c.RetryCount = 0

	c.MarkExecutionFailed()
	if c.State != StateExecuted {
		t.Fatalf("state = %v, want executed", c.State)
	}

	ok := c.Retry()
	if !ok {
		t.Error("expected Retry() to succeed after MarkExecutionFailed → Executed")
	}
	if c.State != StateResumed {
		t.Errorf("state = %v, want resumed", c.State)
	}
	if c.RetryCount != 1 {
		t.Errorf("retry_count = %v, want 1", c.RetryCount)
	}
}

func TestContinuation_CanExecute_RejectsExecuting(t *testing.T) {
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting

	if c.CanExecute() {
		t.Error("CanExecute should return false for executing state")
	}
}

func TestContinuation_IsExecutable_RejectsExecuting(t *testing.T) {
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting

	if c.IsExecutable() {
		t.Error("IsExecutable should return false for executing state")
	}
}

func TestContinuation_CanExecute_Approved(t *testing.T) {
	c := NewContinuation("dec_approved", "shell", "shell:ls")
	c.MarkApproved("admin")

	if !c.CanExecute() {
		t.Error("CanExecute should return true for approved state")
	}
}

func TestInMemoryStore_ClaimForExecution_Approved(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_approved", "shell", "shell:ls")
	c.MarkApproved("admin")
	store.Create(c)

	claimed, ok := store.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("expected claim to succeed for approved continuation")
	}
	if claimed.State != StateExecuting {
		t.Errorf("state after claim = %v, want executing", claimed.State)
	}
}

func TestInMemoryStore_ClaimForExecution_RejectsExecuting(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting
	store.Create(c)

	_, ok := store.ClaimForExecution(c.ContinuationID)
	if ok {
		t.Error("expected claim to fail for already-executing continuation")
	}
}

func TestInMemoryStore_ClaimForRetry_RejectsExecuting(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_exec", "shell", "shell:ls")
	c.State = StateExecuting
	store.Create(c)

	_, ok := store.ClaimForRetry(c.ContinuationID)
	if ok {
		t.Error("expected claim to fail for executing continuation")
	}
}

func TestInMemoryStore_ClaimForExecution_Ready(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_ready", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkReady()
	store.Create(c)

	claimed, ok := store.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("expected claim to succeed for ready continuation")
	}
	if claimed.State != StateExecuting {
		t.Errorf("state after claim = %v, want executing", claimed.State)
	}
}

func TestInMemoryStore_ClaimForExecution_Resumed(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_resumed", "shell", "shell:ls")
	c.State = StateResumed
	store.Create(c)

	claimed, ok := store.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("expected claim to succeed for resumed continuation")
	}
	if claimed.State != StateExecuting {
		t.Errorf("state after claim = %v, want executing", claimed.State)
	}
}

func TestInMemoryStore_RecoverFromExecuting_Success(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_recover", "shell", "shell:ls")
	c.State = StateExecuting
	c.MaxRetries = 3
	store.Create(c)

	rec, ok := store.RecoverFromExecuting(c.ContinuationID)
	if !ok {
		t.Fatal("expected RecoverFromExecuting to succeed")
	}
	if rec.State != StateExecuted {
		t.Errorf("state after recovery = %v, want executed", rec.State)
	}
	if !rec.CanRetry() {
		t.Error("recovered continuation should be retryable")
	}

	stored, _ := store.Get(c.ContinuationID)
	if stored.State != StateExecuted {
		t.Errorf("state in store after recovery = %v, want executed", stored.State)
	}
}

func TestInMemoryStore_RecoverFromExecuting_RejectsNonExecuting(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_recover", "shell", "shell:ls")
	c.MarkApproved("admin")
	store.Create(c)

	_, ok := store.RecoverFromExecuting(c.ContinuationID)
	if ok {
		t.Error("expected RecoverFromExecuting to reject non-executing continuation")
	}
}

func TestInMemoryStore_RecoverFromExecuting_NotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, ok := store.RecoverFromExecuting("cnt_nonexistent")
	if ok {
		t.Error("expected RecoverFromExecuting to fail for nonexistent id")
	}
}

func TestInMemoryStore_ListExecutingIDs(t *testing.T) {
	store := NewInMemoryStore()

	c1 := NewContinuation("dec_e1", "shell", "shell:ls")
	c1.State = StateExecuting
	store.Create(c1)

	c2 := NewContinuation("dec_e2", "shell", "shell:ls")
	c2.State = StateExecuting
	store.Create(c2)

	c3 := NewContinuation("dec_e3", "shell", "shell:ls")
	c3.MarkApproved("admin")
	store.Create(c3)

	ids := store.ListExecutingIDs()
	if len(ids) != 2 {
		t.Errorf("ListExecutingIDs returned %d ids, want 2", len(ids))
	}

	// Recover one, ensure list reflects it
	if _, ok := store.RecoverFromExecuting(c1.ContinuationID); !ok {
		t.Fatal("expected recovery to succeed")
	}
	ids = store.ListExecutingIDs()
	if len(ids) != 1 {
		t.Errorf("ListExecutingIDs after recovery = %d, want 1", len(ids))
	}
}

func TestContinuation_MarkRequeue_FromExecuting(t *testing.T) {
	c := NewContinuation("dec_requeue", "shell", "shell:ls")
	c.State = StateExecuting

	c.MarkRequeue()
	if c.State != StateQueued {
		t.Errorf("state = %v, want queued", c.State)
	}
	if c.QueuedAt == nil {
		t.Error("QueuedAt should be set after MarkRequeue")
	}
}

func TestContinuation_MarkRequeue_FromReady(t *testing.T) {
	c := NewContinuation("dec_requeue", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkReady()

	c.MarkRequeue()
	if c.State != StateQueued {
		t.Errorf("state = %v, want queued", c.State)
	}
}

func TestContinuation_MarkRequeue_RejectsApproved(t *testing.T) {
	c := NewContinuation("dec_requeue", "shell", "shell:ls")
	c.MarkApproved("admin")

	c.MarkRequeue()
	if c.State != StateApproved {
		t.Errorf("state = %v, want approved (unchanged)", c.State)
	}
}

func TestContinuation_MarkRequeue_RejectsTerminal(t *testing.T) {
	c := NewContinuation("dec_requeue", "shell", "shell:ls")
	c.State = StateExecuted

	c.MarkRequeue()
	if c.State != StateExecuted {
		t.Errorf("state = %v, want executed (unchanged)", c.State)
	}
}
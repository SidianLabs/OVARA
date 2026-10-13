package continuation

import "testing"

// G-13: an action that was executing when the gateway stopped may have
// taken effect. Recovery must say "outcome unknown", not "failed,
// retryable", and nothing — retry API or journal — may re-run it.
func TestRecoveredExecutionIsOutcomeUnknown(t *testing.T) {
	s := NewInMemoryStore()
	c := NewContinuation("dec_1", "git.push", "refs/heads/main")
	c.State = StateExecuting
	s.Create(c)
	rec, ok := s.RecoverFromExecuting(c.ContinuationID)
	if !ok {
		t.Fatal("recover failed")
	}
	if rec.State != StateExecuted || !rec.OutcomeUnknown || rec.LastExecutionSucceeded {
		t.Fatalf("recovered: %+v", rec)
	}
	if rec.CanRetry() {
		t.Fatal("an execution with unknown outcome is retryable")
	}
	if info := rec.RetryInfo(); info.Status != "outcome_unknown" || info.CanRetry {
		t.Fatalf("retry info: %+v", info)
	}
	next := *rec
	next.State = StateResumed
	if err := checkTransition(rec, &next); err == nil {
		t.Fatal("the journal accepts a retry of an execution with unknown outcome")
	}
	flip := *rec
	flip.OutcomeUnknown = false
	if err := checkTransition(rec, &flip); err == nil {
		t.Fatal("the journal accepts clearing outcome_unknown")
	}
}

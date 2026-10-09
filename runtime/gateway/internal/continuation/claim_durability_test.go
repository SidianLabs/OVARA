package continuation

import (
	"path/filepath"
	"testing"
)

// A claim that cannot be written to disk must be refused: if the action
// ran anyway, a crash would forget the claim and the restart would run the
// same approved action a second time.
func TestClaimForExecution_RefusedWhenClaimCannotBePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "continuations.jsonl")
	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatal(err)
	}

	c := NewContinuation("dec_claim", "shell", "git push origin main").WithAgentID("agt_claim")
	if err := store.Create(c); err != nil {
		t.Fatal(err)
	}
	c.MarkApproved("operator_1")
	if err := store.Update(c); err != nil {
		t.Fatal(err)
	}

	// Break the journal underneath the store: every append now fails.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if got, ok := store.ClaimForExecution(c.ContinuationID); ok || got != nil {
		t.Fatal("claim succeeded although it could not be persisted; the action would run unrecorded")
	}
	cur, found := store.Get(c.ContinuationID)
	if !found {
		t.Fatal("continuation disappeared")
	}
	if cur.State != StateApproved {
		t.Fatalf("failed claim must roll back to approved, got %s", cur.State)
	}
}

func TestRetryAndCancel_RolledBackWhenNotPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "continuations.jsonl")
	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	c := NewContinuation("dec_cancel", "shell", "deploy").WithAgentID("agt_cancel")
	if err := store.Create(c); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Get(c.ContinuationID)
	store.Close()

	if _, ok := store.CancelForOperation(c.ContinuationID); ok {
		t.Fatal("cancel reported success without being persisted")
	}
	after, _ := store.Get(c.ContinuationID)
	if after.State != before.State {
		t.Fatalf("state changed from %s to %s on a failed write", before.State, after.State)
	}
}

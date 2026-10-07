package continuation

import (
	"path/filepath"
	"testing"
)

// Regression: in signed-journal mode FileBackedStore.Update used to write
// to a nil legacy file handle, so every update failed and the in-memory
// state never advanced (a finished continuation stayed "executing" and was
// later retried by the stuck-execution sweep).
func TestSignedStore_UpdatePersistsAndSurvivesReopen(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")

	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatal(err)
	}

	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_upd"
	c.MarkApproved("admin")
	c.MarkQueued()
	if err := st.Create(c); err != nil {
		t.Fatal(err)
	}

	claimed, ok := st.ClaimForExecution("cont_upd")
	if !ok {
		t.Fatal("claim failed")
	}
	claimed.MarkExecuted()
	if err := st.Update(claimed); err != nil {
		t.Fatalf("Update in signed mode must succeed, got: %v", err)
	}

	got, _ := st.Get("cont_upd")
	if got.State != StateExecuted {
		t.Fatalf("in-memory state = %s, want executed", got.State)
	}
	_ = st.journal.Close()

	// Reopen from disk: the executed state must have been journaled.
	st2, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.journal.Close()
	got2, ok := st2.Get("cont_upd")
	if !ok {
		t.Fatal("continuation missing after reopen")
	}
	if got2.State != StateExecuted {
		t.Fatalf("state after reopen = %s, want executed (update was not durable)", got2.State)
	}
}

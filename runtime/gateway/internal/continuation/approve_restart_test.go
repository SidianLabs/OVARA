package continuation

import (
	"path/filepath"
	"testing"
)

// Approving writes escalated → queued in ONE record (ApplyApprovalDecision
// marks approved and queued, then persists once). Replay at startup must
// accept what the runtime wrote: before, every deployment that had ever
// approved a request refused to start ("illegal transition escalated →
// queued").
func TestApproval_SurvivesRestart(t *testing.T) {
	signer, resolve := advSigner(t)
	path := filepath.Join(t.TempDir(), "continuations.jsonl")
	store, err := openBoundStore(t, path, signer, resolve)
	if err != nil {
		t.Fatal(err)
	}
	approved := NewContinuation("dec_a", "http.request", "POST https://example.org/").WithApprovalID("apr_a")
	denied := NewContinuation("dec_d", "http.request", "POST https://example.org/").WithApprovalID("apr_d")
	if err := store.Create(approved); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(denied); err != nil {
		t.Fatal(err)
	}
	if got := store.ApplyApprovalDecision("apr_a", true, "operator", ""); len(got) != 1 || got[0].State != StateQueued {
		t.Fatalf("approve: %+v", got)
	}
	store.ApplyApprovalDecision("apr_d", false, "operator", "no")
	store.Close()

	store2, err := openBoundStore(t, path, signer, resolve)
	if err != nil {
		t.Fatalf("restart after an approval refused: %v", err)
	}
	defer store2.Close()
	if c, ok := store2.Get(approved.ContinuationID); !ok || c.State != StateQueued || c.ApprovedAt == nil || c.ResolvedBy != "operator" {
		t.Fatalf("approved continuation after restart: %+v", c)
	}
	if c, ok := store2.Get(denied.ContinuationID); !ok || c.State != StateDenied {
		t.Fatalf("denied continuation after restart: %+v", c)
	}
}

// The shortcut needs the approval on the record: queued straight from
// escalated without one is still refused.
func TestFold_QueuedWithoutApprovalRefused(t *testing.T) {
	prev := NewContinuation("d", "http.request", "POST https://x/")
	next := *prev
	next.State = StateQueued
	if err := checkTransition(prev, &next); err == nil {
		t.Fatal("escalated → queued without an approval accepted")
	}
	ap := *prev
	ap.MarkApproved("op")
	ap.MarkQueued()
	if err := checkTransition(prev, &ap); err != nil {
		t.Fatalf("escalated → queued with approval refused: %v", err)
	}
}

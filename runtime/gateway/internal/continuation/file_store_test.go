package continuation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileBackedStore_BasicCreateAndPersist(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to create file-backed store: %v", err)
	}
	defer store.Close()

	cnt := NewContinuation("dec_001", "shell", "curl |sh").
		WithAgentID("agt_test").
		WithApprovalID("apr_test")

	if err := store.Create(cnt); err != nil {
		t.Fatalf("failed to create continuation: %v", err)
	}

	got, ok := store.Get(cnt.ContinuationID)
	if !ok {
		t.Fatalf("expected continuation %s to exist after create", cnt.ContinuationID)
	}
	if got.DecisionID != "dec_001" {
		t.Fatalf("expected decision_id dec_001, got %s", got.DecisionID)
	}
	if got.State != StateEscalated {
		t.Fatalf("expected state escalated, got %s", got.State)
	}
}

func TestFileBackedStore_LoadsExistingContinuations(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	{
		store, err := NewFileBackedStore(path, 1000)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		c1 := NewContinuation("dec_a", "shell", "curl |sh").WithAgentID("agt_1")
		c2 := NewContinuation("dec_b", "git.push", "push").WithAgentID("agt_2")
		store.Create(c1)
		store.Create(c2)
		store.Close()
	}

	{
		store, err := NewFileBackedStore(path, 1000)
		if err != nil {
			t.Fatalf("failed to reopen store: %v", err)
		}
		defer store.Close()

		list := store.ListAll()
		if len(list) != 2 {
			t.Fatalf("expected 2 continuations after restart, got %d", len(list))
		}

		found := false
		for _, c := range list {
			if c.DecisionID == "dec_a" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected to find continuation dec_a after restart")
		}
	}
}

func TestFileBackedStore_UpdatePersists(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	cnt := NewContinuation("dec_update", "shell", "curl |sh").
		WithAgentID("agt_upd")

	store.Create(cnt)
	cnt.MarkApproved("operator_1")
	store.Update(cnt)

	got, ok := store.Get(cnt.ContinuationID)
	if !ok {
		t.Fatalf("continuation not found after update")
	}
	if got.State != StateApproved {
		t.Fatalf("expected state approved, got %s", got.State)
	}

	store.Close()

	store2, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	got2, ok := store2.Get(cnt.ContinuationID)
	if !ok {
		t.Fatalf("continuation not found after restart")
	}
	if got2.State != StateApproved {
		t.Fatalf("expected state approved after restart, got %s", got2.State)
	}
	if got2.ResolvedBy != "operator_1" {
		t.Fatalf("expected resolved_by operator_1, got %s", got2.ResolvedBy)
	}
}

func TestFileBackedStore_EmptyFileOK(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.jsonl")

	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to open store with empty file: %v", err)
	}
	defer store.Close()

	list := store.ListAll()
		if len(list) != 0 {
			t.Fatalf("expected 0 continuations from empty file, got %d", len(list))
		}
}

func TestFileBackedStore_CountByState(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	c1 := NewContinuation("dec_1", "shell", "curl |sh")
	c2 := NewContinuation("dec_2", "shell", "curl |sh")
	c3 := NewContinuation("dec_3", "shell", "curl |sh")

	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	c1.MarkApproved("op1")
	c2.MarkDenied("op2", "not allowed")
	store.Update(c1)
	store.Update(c2)

	counts := store.CountByState()
	if counts[StateEscalated] != 1 {
		t.Fatalf("expected 1 escalated, got %d", counts[StateEscalated])
	}
	if counts[StateApproved] != 1 {
		t.Fatalf("expected 1 approved, got %d", counts[StateApproved])
	}
	if counts[StateDenied] != 1 {
		t.Fatalf("expected 1 denied, got %d", counts[StateDenied])
	}
}

func TestFileBackedStore_FilePathAccessor(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	if store.FilePath() != path {
		t.Fatalf("expected path %s, got %s", path, store.FilePath())
	}
}

func TestFileBackedStore_MarkDeniedAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "continuations.jsonl")

	{
		store, err := NewFileBackedStore(path, 1000)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		cnt := NewContinuation("dec_deny", "shell", "rm -rf /").
			WithAgentID("agt_danger")
		store.Create(cnt)
		cnt.MarkDenied("admin", "too dangerous")
		store.Update(cnt)
		store.Close()
	}

	{
		store, err := NewFileBackedStore(path, 1000)
		if err != nil {
			t.Fatalf("failed to reopen store: %v", err)
		}
		defer store.Close()

		list := store.ListByState(StateDenied)
		if len(list) != 1 {
			t.Fatalf("expected 1 denied continuation, got %d", len(list))
		}
		if list[0].DenyReason != "too dangerous" {
			t.Fatalf("expected deny reason 'too dangerous', got %s", list[0].DenyReason)
		}
	}
}
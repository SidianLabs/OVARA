package events

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileBackedStore_BasicAppendAndPersist(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	store, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	e1 := NewEvent(EventTypeDecisionEvaluated).WithDecisionID("dec_1").WithAgentID("agt_test")
	e2 := NewEvent(EventTypeReceiptIssued).WithReceiptID("rcpt_1")
	store.Append(e1)
	store.Append(e2)

	if store.Count() != 2 {
		t.Errorf("count = %d, want 2", store.Count())
	}

	store.Close()

	store2, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	if store2.Count() != 2 {
		t.Errorf("after reopen count = %d, want 2", store2.Count())
	}

	events := store2.List(10)
	if len(events) != 2 {
		t.Errorf("list length = %d, want 2", len(events))
	}
}

func TestFileBackedStore_LoadsExistingEvents(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	store, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	for i := 0; i < 5; i++ {
		e := NewEvent(EventTypeDecisionEvaluated).WithDecisionID("dec_" + string(rune('0'+i)))
		store.Append(e)
	}
	store.Close()

	store2, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	if store2.Count() != 5 {
		t.Errorf("count = %d, want 5", store2.Count())
	}

	if store2.LoadedCount() != 5 {
		t.Errorf("loaded_count = %d, want 5", store2.LoadedCount())
	}
}

func TestFileBackedStore_EmptyFileOK(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	f.Close()

	store, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to open empty file: %v", err)
	}
	defer store.Close()

	if store.Count() != 0 {
		t.Errorf("count = %d, want 0 for empty file", store.Count())
	}
}

func TestFileBackedStore_FilePath(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	store, err := NewFileBackedStore(path, 100)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	if store.FilePath() != path {
		t.Errorf("filepath = %s, want %s", store.FilePath(), path)
	}
}
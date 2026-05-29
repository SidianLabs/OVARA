package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func TestFileBackedStore_ConcurrentAppendAndList(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	store, err := NewFileBackedStore(path, 1000)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e := NewEvent(EventTypeDecisionEvaluated).WithDecisionID(fmt.Sprintf("dec_%d_%d", i, j))
				store.Append(e)
			}
		}(i)
	}
	wg.Wait()

	count := store.Count()
	if count != 1000 {
		t.Errorf("count = %d, want 1000", count)
	}

	list := store.List(0)
	if len(list) != 1000 {
		t.Errorf("list length = %d, want 1000", len(list))
	}
}

func TestFileBackedStore_ConcurrentAppendAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "events.jsonl")

	store, err := NewFileBackedStore(path, 5000)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	var appended []*Event
	for i := 0; i < 100; i++ {
		e := NewEvent(EventTypeApprovalCreated).WithApprovalID(fmt.Sprintf("apr_%d", i))
		store.Append(e)
		appended = append(appended, e)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			e := NewEvent(EventTypeApprovalCreated).WithApprovalID(fmt.Sprintf("new_%d", i))
			store.Append(e)
		}
	}()

	for _, e := range appended {
		wg.Add(1)
		go func(evt *Event) {
			defer wg.Done()
			got, ok := store.Get(evt.EventID)
			if !ok {
				t.Errorf("Get(%s) not found", evt.EventID)
				return
			}
			if got.EventID != evt.EventID {
				t.Errorf("Get(%s) event_id mismatch", evt.EventID)
			}
		}(e)
	}
	wg.Wait()
}
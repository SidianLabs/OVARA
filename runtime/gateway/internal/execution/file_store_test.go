package execution

import (
	"context"
	"path/filepath"
	"testing"
)

func TestFileBackedStore_CreateAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hello", 60)
	if err := store.Create(e1); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:ls", 60)
	if err := store.Create(e2); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	store.Close()

	store2, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}
	defer store2.Close()

	got1, ok := store2.Get(e1.ExecutionID)
	if !ok {
		t.Fatal("expected to find e1 after reload")
	}
	if got1.ContinuationID != "cnt_1" {
		t.Errorf("continuation_id = %s, want cnt_1", got1.ContinuationID)
	}

	got2, ok := store2.Get(e2.ExecutionID)
	if !ok {
		t.Fatal("expected to find e2 after reload")
	}
	if got2.ContinuationID != "cnt_2" {
		t.Errorf("continuation_id = %s, want cnt_2", got2.ContinuationID)
	}

	if store2.loadedCount != 2 {
		t.Errorf("loadedCount = %d, want 2", store2.loadedCount)
	}
}

func TestFileBackedStore_UpdateAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	if err := store.Create(e); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	e.MarkSucceeded(0, "hello world", "")
	if err := store.Update(e); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	store.Close()

	store2, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}
	defer store2.Close()

	got, ok := store2.Get(e.ExecutionID)
	if !ok {
		t.Fatal("expected to find execution after reload")
	}
	if got.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", got.State)
	}
	if got.Stdout != "hello world" {
		t.Errorf("stdout = %s, want hello world", got.Stdout)
	}
}

func TestFileBackedStore_ListByContinuation(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_a", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := NewExecution("cnt_a", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e3 := NewExecution("cnt_b", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)

	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	list := store.ListByContinuation("cnt_a")
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}

	list = store.ListByContinuation("cnt_b")
	if len(list) != 1 {
		t.Errorf("len = %d, want 1", len(list))
	}
}

func TestFileBackedStore_ListByState(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e3 := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)

	store.Create(e1)
	store.Create(e2)
	store.Create(e3)

	e1.MarkSucceeded(0, "out", "")
	e2.MarkFailed("err", 1)
	store.Update(e1)
	store.Update(e2)

	succeeded := store.ListByState(StateSucceeded)
	if len(succeeded) != 1 {
		t.Errorf("len succeeded = %d, want 1", len(succeeded))
	}

	failed := store.ListByState(StateFailed)
	if len(failed) != 1 {
		t.Errorf("len failed = %d, want 1", len(failed))
	}

	pending := store.ListByState(StatePending)
	if len(pending) != 1 {
		t.Errorf("len pending = %d, want 1", len(pending))
	}
}

func TestFileBackedStore_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e3 := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	e4 := NewExecution("cnt_4", "dec_4", "apr_4", "agt_4", "shell", "shell:echo d", 60)

	store.Create(e1)
	store.Create(e2)
	store.Create(e3)
	store.Create(e4)

	e1.MarkSucceeded(0, "", "")
	e2.MarkFailed("err", 1)
	e3.MarkStarted()
	store.Update(e1)
	store.Update(e2)
	store.Update(e3)

	total, succeeded, failed, running, timedOut := store.Stats()
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if succeeded != 1 {
		t.Errorf("succeeded = %d, want 1", succeeded)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if running != 1 {
		t.Errorf("running = %d, want 1", running)
	}
	if timedOut != 0 {
		t.Errorf("timedOut = %d, want 0", timedOut)
	}
}

func TestFileBackedStore_FilePath(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	if store.FilePath() != storePath {
		t.Errorf("FilePath = %s, want %s", store.FilePath(), storePath)
	}
}

func TestFileBackedStore_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "nonexistent", "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed for nonexistent path: %v", err)
	}
	defer store.Close()

	if store.FilePath() != storePath {
		t.Errorf("FilePath = %s, want %s", store.FilePath(), storePath)
	}
}

func TestFileBackedStore_ReloadEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	{
		store, err := NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("NewFileBackedStore failed: %v", err)
		}
		store.Close()
	}

	{
		store, err := NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("NewFileBackedStore reload failed: %v", err)
		}
		defer store.Close()

		if store.loadedCount != 0 {
			t.Errorf("loadedCount = %d, want 0", store.loadedCount)
		}
		all := store.ListAll()
		if len(all) != 0 {
			t.Errorf("len = %d, want 0", len(all))
		}
	}
}

func TestFileBackedStore_CreateDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	if err := store.Create(e); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = store.Create(e)
	if err == nil {
		t.Error("expected error for duplicate execution")
	}
}

func TestFileBackedStore_UpdateNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStore(storePath, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}
	defer store.Close()

	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	err = store.Update(e)
	if err == nil {
		t.Error("expected error for update of nonexistent execution")
	}
}

func TestFileBackedStore_LoadedCountAfterReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	{
		store, err := NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("NewFileBackedStore failed: %v", err)
		}
		for i := 0; i < 5; i++ {
			e := NewExecution("cnt_"+string(rune('a'+i)), "dec", "apr", "agt", "shell", "shell:echo", 60)
			store.Create(e)
		}
		store.Close()
	}

	{
		store2, err := NewFileBackedStore(storePath, 1000)
		if err != nil {
			t.Fatalf("NewFileBackedStore reload failed: %v", err)
		}
		defer store2.Close()

		if store2.loadedCount != 5 {
			t.Errorf("loadedCount = %d, want 5", store2.loadedCount)
		}
	}
}

func TestExecution_TimeoutState(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutor(1)
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:sleep 2", 1)
	exec.Execute(ctx, e)
	if e.State != StateTimedOut {
		t.Errorf("state = %s, want timed_out", e.State)
	}
}
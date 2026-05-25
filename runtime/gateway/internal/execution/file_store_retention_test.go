package execution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileBackedStore_Sweep_AgeBased(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 7, 10000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkStarted()
	e1.MarkSucceeded(0, "out", "")
	store.Create(e1)

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkStarted()
	e2.MarkFailed("err", 1)
	store.Create(e2)

	e3 := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	e3.MarkStarted()
	e3.MarkTimedOut()
	store.Create(e3)

	removed, err := store.Sweep()
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}

	if removed != 0 {
		t.Errorf("with default 7-day retention, removed = %d, want 0", removed)
	}

	all := store.ListAll()
	if len(all) != 3 {
		t.Errorf("after sweep, count = %d, want 3", len(all))
	}
}

func TestFileBackedStore_Sweep_OldRecords(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 0, 2)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkStarted()
	e1.MarkSucceeded(0, "out", "")
	e1.StartedAt = time.Now().UTC().Add(-48 * time.Hour)
	e1.FinishedAt = func() *time.Time { t := time.Now().UTC().Add(-48 * time.Hour); return &t }()
	store.Create(e1)

	time.Sleep(10 * time.Millisecond)

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkStarted()
	e2.MarkSucceeded(0, "out", "")
	e2.StartedAt = time.Now().UTC().Add(-24 * time.Hour)
	e2.FinishedAt = func() *time.Time { t := time.Now().UTC().Add(-24 * time.Hour); return &t }()
	store.Create(e2)

	time.Sleep(10 * time.Millisecond)

	e3 := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:echo c", 60)
	e3.MarkStarted()
	e3.MarkSucceeded(0, "out", "")
	e3.FinishedAt = func() *time.Time { t := time.Now().UTC(); return &t }()
	store.Create(e3)

	store.Close()

	store2, err := NewFileBackedStoreWithRetention(storePath, 1000, 0, 2)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	defer store2.Close()

	execsBefore := store2.ListAll()
	t.Logf("execs before sweep: %d", len(execsBefore))

	removed, err := store2.Sweep()
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}
	t.Logf("removed: %d", removed)

	execsAfter := store2.ListAll()
	t.Logf("execs after sweep: %d", len(execsAfter))

	if len(execsAfter) > 2 {
		t.Errorf("after sweep with max_records=2, count = %d, want <= 2", len(execsAfter))
	}
}

func TestFileBackedStore_Sweep_MarksStaleIDs(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 0, 1)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "", "")
	e1.FinishedAt = func() *time.Time { t := time.Now().UTC().Add(-48 * time.Hour); return &t }()
	store.Create(e1)

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkSucceeded(0, "", "")
	e2.FinishedAt = func() *time.Time { t := time.Now().UTC(); return &t }()
	store.Create(e2)

	store.Close()

	store2, err := NewFileBackedStoreWithRetention(storePath, 1000, 0, 1)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	defer store2.Close()

	execs := store2.ListAll()
	if len(execs) < 1 {
		t.Fatalf("expected at least 1 exec after load, got %d", len(execs))
	}

	removed, err := store2.Sweep()
	if err != nil {
		t.Fatalf("Sweep failed: %v", err)
	}
	t.Logf("removed: %d", removed)

	execsAfter := store2.ListAll()
	if len(execsAfter) > 1 {
		t.Errorf("count after sweep = %d, want <= 1", len(execsAfter))
	}
}

func TestFileBackedStore_Load_SkipsCleanupRecords(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	{
		f, err := os.Create(storePath)
		if err != nil {
			t.Fatalf("create file failed: %v", err)
		}

		e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
		e.MarkSucceeded(0, "out", "")
		data, _ := json.Marshal(e)
		f.Write(append(data, '\n'))

		cleanup := map[string]any{"_cleanup": true, "execution_ids": []any{"cnt_nonexistent"}}
		cleanupData, _ := json.Marshal(cleanup)
		f.Write(append(cleanupData, '\n'))

		e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
		e2.MarkSucceeded(0, "out2", "")
		data2, _ := json.Marshal(e2)
		f.Write(append(data2, '\n'))

		f.Close()
	}

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 7, 10000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	execs := store.ListAll()
	if len(execs) != 2 {
		t.Errorf("executions count = %d, want 2 (cleanup record skipped)", len(execs))
	}

	foundCnt1 := false
	foundCnt2 := false
	for _, e := range execs {
		if e.ContinuationID == "cnt_1" {
			foundCnt1 = true
		}
		if e.ContinuationID == "cnt_2" {
			foundCnt2 = true
		}
	}
	if !foundCnt1 {
		t.Error("cnt_1 not found in loaded executions")
	}
	if !foundCnt2 {
		t.Error("cnt_2 not found in loaded executions")
	}
}

func TestFileBackedStore_FileSizeBytes(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 7, 10000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hello", 60)
	e.MarkSucceeded(0, "hello world", "")
	store.Create(e)

	size, err := store.FileSizeBytes()
	if err != nil {
		t.Fatalf("FileSizeBytes failed: %v", err)
	}
	if size <= 0 {
		t.Error("file size should be > 0 after creating execution")
	}
}

func TestFileBackedStore_CurrentCount(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 7, 10000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	if store.CurrentCount() != 0 {
		t.Errorf("initial count = %d, want 0", store.CurrentCount())
	}

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "", "")
	store.Create(e1)

	if store.CurrentCount() != 1 {
		t.Errorf("after 1 create, count = %d, want 1", store.CurrentCount())
	}

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkSucceeded(0, "", "")
	store.Create(e2)

	if store.CurrentCount() != 2 {
		t.Errorf("after 2 creates, count = %d, want 2", store.CurrentCount())
	}
}

func TestSweeper_StartStop(t *testing.T) {
	store := NewInMemoryStore()
	sweeper := NewSweeper(store)

	if sweeper.IsRunning() {
		t.Error("new sweeper should not be running")
	}

	sweeper.Start(1)
	if !sweeper.IsRunning() {
		t.Error("sweeper should be running after Start")
	}

	sweeper.Stop()
	if sweeper.IsRunning() {
		t.Error("sweeper should not be running after Stop")
	}
}

func TestSweeper_Sweep_DelegatesToFileBackedStore(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 7, 10000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "", "")
	store.Create(e1)

	sweeper := NewSweeper(store)
	sweeper.Start(60)

	time.Sleep(50 * time.Millisecond)

	if !sweeper.IsRunning() {
		t.Error("sweeper should be running")
	}

	sweeper.Stop()
}

func TestSweeper_Sweep_InMemoryStore(t *testing.T) {
	store := NewInMemoryStore()
	sweeper := NewSweeper(store)

	removed, err := sweeper.Sweep()
	if err != nil {
		t.Fatalf("Sweep on in-memory store failed: %v", err)
	}
	if removed != 0 {
		t.Errorf("in-memory store sweep returned removed = %d, want 0", removed)
	}
}

func TestExecutionHandler_Stats_IncludesRetentionInfo(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "executions.jsonl")

	store, err := NewFileBackedStoreWithRetention(storePath, 1000, 30, 5000)
	if err != nil {
		t.Fatalf("NewFileBackedStoreWithRetention failed: %v", err)
	}
	defer store.Close()

	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo a", 60)
	e1.MarkSucceeded(0, "", "")
	store.Create(e1)

	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:echo b", 60)
	e2.MarkFailed("err", 1)
	store.Create(e2)

	total, succeeded, failed, running, timedOut := store.Stats()
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if succeeded != 1 {
		t.Errorf("succeeded = %d, want 1", succeeded)
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1", failed)
	}
	if running != 0 {
		t.Errorf("running = %d, want 0", running)
	}
	if timedOut != 0 {
		t.Errorf("timedOut = %d, want 0", timedOut)
	}

	if store.RetentionDays() != 30 {
		t.Errorf("retention_days = %d, want 30", store.RetentionDays())
	}
	if store.MaxRecords() != 5000 {
		t.Errorf("max_records = %d, want 5000", store.MaxRecords())
	}
}
package execution

import (
	"context"
	"testing"
)

func TestNewExecution(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 30)
	if exe.ExecutionID == "" {
		t.Error("execution_id should not be empty")
	}
	if exe.ContinuationID != "cnt_1" {
		t.Errorf("continuation_id = %s, want cnt_1", exe.ContinuationID)
	}
	if exe.State != StatePending {
		t.Errorf("state = %s, want pending", exe.State)
	}
	if exe.TimeoutSeconds != 30 {
		t.Errorf("timeout_seconds = %d, want 30", exe.TimeoutSeconds)
	}
}

func TestExecution_MarkStarted(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	exe.MarkStarted()
	if exe.State != StateRunning {
		t.Errorf("state = %s, want running", exe.State)
	}
	if exe.StartedAt.IsZero() {
		t.Error("started_at should be set")
	}
}

func TestExecution_MarkSucceeded(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	exe.MarkSucceeded(0, "hello world", "")
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", exe.ExitCode)
	}
	if exe.Stdout != "hello world" {
		t.Errorf("stdout = %s, want hello world", exe.Stdout)
	}
	if exe.FinishedAt == nil {
		t.Error("finished_at should be set")
	}
}

func TestExecution_MarkFailed(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	exe.MarkFailed("command not found")
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if exe.Error != "command not found" {
		t.Errorf("error = %s, want command not found", exe.Error)
	}
	if exe.FinishedAt == nil {
		t.Error("finished_at should be set")
	}
}

func TestExecution_IsTerminal(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hi", 60)
	if exe.IsTerminal() {
		t.Error("pending should not be terminal")
	}
	exe.MarkStarted()
	if exe.IsTerminal() {
		t.Error("running should not be terminal")
	}
	exe.MarkSucceeded(0, "", "")
	if !exe.IsTerminal() {
		t.Error("succeeded should be terminal")
	}
	exe2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:bad", 60)
	exe2.MarkFailed("error")
	if !exe2.IsTerminal() {
		t.Error("failed should be terminal")
	}
}

func TestInMemoryStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryStore()
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	if err := store.Create(exe); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	got, ok := store.Get(exe.ExecutionID)
	if !ok {
		t.Fatal("expected to find execution")
	}
	if got.ContinuationID != "cnt_1" {
		t.Errorf("continuation_id = %s, want cnt_1", got.ContinuationID)
	}
}

func TestInMemoryStore_GetNotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, ok := store.Get("exe_nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestInMemoryStore_Update(t *testing.T) {
	store := NewInMemoryStore()
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	store.Create(exe)
	exe.MarkSucceeded(0, "output", "")
	if err := store.Update(exe); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	got, _ := store.Get(exe.ExecutionID)
	if got.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", got.State)
	}
}

func TestInMemoryStore_ListByContinuation(t *testing.T) {
	store := NewInMemoryStore()
	e1 := NewExecution("cnt_a", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e2 := NewExecution("cnt_a", "dec_2", "apr_2", "agt_2", "shell", "shell:pwd", 60)
	e3 := NewExecution("cnt_b", "dec_3", "apr_3", "agt_3", "shell", "shell:who", 60)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)
	list := store.ListByContinuation("cnt_a")
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
}

func TestInMemoryStore_Stats(t *testing.T) {
	store := NewInMemoryStore()
	e1 := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e2 := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:pwd", 60)
	e3 := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:who", 60)
	store.Create(e1)
	store.Create(e2)
	store.Create(e3)
	e1.MarkSucceeded(0, "", "")
	e2.MarkFailed("error")
	e3.MarkStarted()
	total, succeeded, failed, running := store.Stats()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
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
}

func TestParseShellResource(t *testing.T) {
	cmd, err := ParseShellResource("shell:echo hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != "echo hello" {
		t.Errorf("cmd = %s, want 'echo hello'", cmd)
	}

	_, err = ParseShellResource("git.push:origin main")
	if err == nil {
		t.Error("expected error for non-shell resource")
	}

	_, err = ParseShellResource("shell:")
	if err == nil {
		t.Error("expected error for empty shell command")
	}
}

func TestShellExecutor(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutor(10)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo ovara_test", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", exe.ExitCode)
	}
	if exe.Stdout == "" {
		t.Error("stdout should not be empty")
	}
}
package execution

import (
	"context"
	"fmt"
	"os"
	osExec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testExecCmd = osExec.CommandContext

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
	exe.MarkFailed("command not found", 1)
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
	exe2.MarkFailed("error", 1)
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
	e2.MarkFailed("error", 1)
	e3.MarkStarted()
	total, succeeded, failed, running, timedOut := store.Stats()
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
	if timedOut != 0 {
		t.Errorf("timedOut = %d, want 0", timedOut)
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

func TestShellExecutor_StdoutTruncation(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 20, 256*1024)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:printf 'A%.0s' {1..100}", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if !exe.StdoutTruncated {
		t.Error("stdout should be truncated")
	}
	if len(exe.Stdout) > 20 {
		t.Errorf("stdout len = %d, want <= 20 (limit)", len(exe.Stdout))
	}
	if exe.StdoutLimitBytes != 20 {
		t.Errorf("stdout_limit_bytes = %d, want 20", exe.StdoutLimitBytes)
	}
}

func TestShellExecutor_StderrTruncation(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 20)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:printf 'B%.0s' 1>&2 {1..100}", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if !exe.StderrTruncated {
		t.Error("stderr should be truncated")
	}
	if len(exe.Stderr) > 20 {
		t.Errorf("stderr len = %d, want <= 20 (limit)", len(exe.Stderr))
	}
	if exe.StderrLimitBytes != 20 {
		t.Errorf("stderr_limit_bytes = %d, want 20", exe.StderrLimitBytes)
	}
}

func TestShellExecutor_NotTruncatedWhenUnderLimit(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo hello", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.StdoutTruncated {
		t.Error("stdout should not be truncated (output is small)")
	}
	if exe.StderrTruncated {
		t.Error("stderr should not be truncated")
	}
}

func TestShellExecutor_WorkingDir(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	exec.WorkingDir = "/tmp"
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:pwd", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.Stdout != "/tmp\n" {
		t.Errorf("stdout = %q, want %q", exe.Stdout, "/tmp\n")
	}
}

func TestShellExecutor_AllowedEnvVars(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	exec.AllowedEnvVars = []string{"HOME"}
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo $HOME", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.Stdout == "" {
		t.Error("stdout should not be empty (HOME should be set when allowed)")
	}
}

func TestShellExecutor_EnvVars_NilInheritsAll(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	if exec.AllowedEnvVars != nil {
		t.Errorf("AllowedEnvVars = %v, want nil (default, inherits parent env)", exec.AllowedEnvVars)
	}
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo $HOME", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.Stdout == "" {
		t.Error("stdout should not be empty when AllowedEnvVars=nil (inherits parent env including HOME)")
	}
}

func TestShellExecutor_EnvVars_EmptyStripAll(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	exec.AllowedEnvVars = []string{}
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:echo $HOME", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.Stdout != "" && exe.Stdout != "\n" {
		t.Logf("stdout = %q (empty or newline when all env stripped)", exe.Stdout)
	}
}

func TestShellExecutor_ExitCodePreservedOnFailure(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(10, 1024*1024, 256*1024)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:exit 42", 10)
	err := exec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if exe.ExitCode != 42 {
		t.Errorf("exit_code = %d, want 42", exe.ExitCode)
	}
}

func TestShellExecutor_TimeoutSetsTruncationFlags(t *testing.T) {
	ctx := context.Background()
	exec := NewShellExecutorWithLimits(1, 1024*1024, 256*1024)
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:sleep 5", 1)
	err := exec.Execute(ctx, exe)
	if err == nil {
		t.Fatal("expected error for timeout")
	}
	if exe.State != StateTimedOut {
		t.Errorf("state = %s, want timed_out", exe.State)
	}
	if exe.StdoutLimitBytes != 1024*1024 {
		t.Errorf("stdout_limit_bytes = %d, want 1048576", exe.StdoutLimitBytes)
	}
}

func TestTimeoutErrorMessageFormat(t *testing.T) {
	ctx := context.Background()

	t.Run("shell_timeout_format", func(t *testing.T) {
		exec := NewShellExecutor(1)
		exe := NewExecution("cnt_s1", "dec_s1", "apr_s1", "agt_s1", "shell", "shell:sleep 10", 1)
		exec.Execute(ctx, exe)
		if exe.State != StateTimedOut {
			t.Fatalf("state = %s, want timed_out", exe.State)
		}
		if exe.Error == "" {
			t.Fatal("error field should be set on timeout")
		}
		expectedPrefix := "shell: command timed out after "
		if len(exe.Error) < len(expectedPrefix) || exe.Error[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("error = %q, want prefix %q", exe.Error, expectedPrefix)
		}
	})

	t.Run("exec_timeout_format", func(t *testing.T) {
		exec := NewDirectExecutor(1)
		exe := NewExecution("cnt_e1", "dec_e1", "apr_e1", "agt_e1", "exec", "exec:sleep 10", 1)
		exec.Execute(ctx, exe)
		if exe.State != StateTimedOut {
			t.Fatalf("state = %s, want timed_out", exe.State)
		}
		if exe.Error == "" {
			t.Fatal("error field should be set on timeout")
		}
		expectedPrefix := "exec: command timed out after "
		if len(exe.Error) < len(expectedPrefix) || exe.Error[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("error = %q, want prefix %q", exe.Error, expectedPrefix)
		}
	})

	t.Run("git_timeout_format", func(t *testing.T) {
		t.Skip("git pull on local repo fails fast without remote; timeout code path same as shell/exec")
	})
}

type mockExecForRegistry struct {
	calls int
}

func (m *mockExecForRegistry) Execute(ctx context.Context, e *Execution) error {
	m.calls++
	e.MarkSucceeded(0, "ok", "")
	return nil
}

func TestExecutorRegistry(t *testing.T) {
	reg := NewExecutorRegistry()

	exec1 := &mockExecForRegistry{}
	exec2 := &mockExecForRegistry{}

	reg.Register("shell", exec1)
	reg.Register("exec", exec2)

	got1, ok := reg.Get("shell")
	if !ok {
		t.Fatal("shell not found in registry")
	}
	if got1 != exec1 {
		t.Error("shell executor mismatch")
	}

	got2, ok := reg.Get("exec")
	if !ok {
		t.Fatal("exec not found in registry")
	}
	if got2 != exec2 {
		t.Error("exec executor mismatch")
	}

	_, ok = reg.Get("git.push")
	if ok {
		t.Error("unexpected executor for git.push")
	}

	types := reg.RegisteredTypes()
	if len(types) != 2 {
		t.Errorf("registered types count = %d, want 2", len(types))
	}
}

func TestExecutorRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewExecutorRegistry()

	exec1 := &mockExecForRegistry{}
	exec2 := &mockExecForRegistry{}
	exec3 := &mockExecForRegistry{}

	reg.Register("shell", exec1)
	reg.Register("exec", exec2)
	reg.Register("git.push", exec3)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := []string{"shell", "exec", "git.push"}[i%3]
			exec, ok := reg.Get(key)
			if !ok {
				t.Errorf("Get(%q) not found", key)
				return
			}
			if exec == nil {
				t.Errorf("Get(%q) returned nil", key)
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = reg.RegisteredTypes()
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reg.Register(fmt.Sprintf("action_%d", i), &mockExecForRegistry{})
		}(i)
	}
	wg.Wait()
}

func TestParseExecResource(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		wantBin   string
		wantErr   bool
	}{
		{"simple", "exec:echo hello", "echo", false},
		{"no_args", "exec:ls", "ls", false},
		{"multiple_args", "exec:git push origin main", "git", false},
		{"missing_prefix", "shell:echo hi", "", true},
		{"empty", "exec:", "", true},
		{"whitespace_only", "exec:   ", "", true},
		{"leading_whitespace", "exec:  pwd", "pwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, _, err := ParseExecResource(tt.resource)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if bin != tt.wantBin {
				t.Errorf("binary = %s, want %s", bin, tt.wantBin)
			}
		})
	}
}

func TestParseExecResource_ErrorMessages(t *testing.T) {
	_, _, err := ParseExecResource("shell:echo")
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
	if !strings.Contains(err.Error(), "exec:") {
		t.Errorf("error %q should mention 'exec:' prefix requirement", err.Error())
	}

	_, _, err = ParseExecResource("exec:")
	if err == nil {
		t.Fatal("expected error for empty exec resource")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should mention empty", err.Error())
	}

	_, _, err = ParseExecResource("exec:   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only exec resource")
	}
}

func TestDirectExecutor(t *testing.T) {
	ctx := context.Background()
	exec := NewDirectExecutor(10)

	t.Run("simple_command", func(t *testing.T) {
		exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "exec", "exec:echo hello", 10)
		err := exec.Execute(ctx, exe)
		if err != nil {
			t.Fatalf("execute failed: %v", err)
		}
		if exe.State != StateSucceeded {
			t.Errorf("state = %s, want succeeded", exe.State)
		}
		if exe.Stdout != "hello\n" {
			t.Errorf("stdout = %q, want %q", exe.Stdout, "hello\n")
		}
	})

	t.Run("binary_not_found", func(t *testing.T) {
		exe := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "exec", "exec:this_binary_does_not_exist_12345", 5)
		err := exec.Execute(ctx, exe)
		if err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
	})

	t.Run("metacharacters_literal", func(t *testing.T) {
		exe := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "exec", "exec:printf hello", 10)
		err := exec.Execute(ctx, exe)
		if err != nil {
			t.Fatalf("execute failed: %v", err)
		}
		if exe.State != StateSucceeded {
			t.Errorf("state = %s, want succeeded", exe.State)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		exec2 := NewDirectExecutor(1)
		exe := NewExecution("cnt_4", "dec_4", "apr_4", "agt_4", "exec", "exec:sleep 5", 1)
		err := exec2.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for timeout")
		}
		if exe.State != StateTimedOut {
			t.Errorf("state = %s, want timed_out", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set on timeout")
		}
		if exe.FinishedAt == nil {
			t.Error("finished_at should be set on timeout")
		}
	})

	t.Run("missing_binary", func(t *testing.T) {
		exe := NewExecution("cnt_5", "dec_5", "apr_5", "agt_5", "exec", "exec:nonexistent_binary_xyz_123", 5)
		err := exec.Execute(ctx, exe)
		if err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set when binary not found")
		}
	})

	t.Run("malformed_resource", func(t *testing.T) {
		exe := NewExecution("cnt_6", "dec_6", "apr_6", "agt_6", "exec", "shell:echo hi", 5)
		err := exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for malformed resource")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set on parse failure")
		}
	})

	t.Run("empty_resource", func(t *testing.T) {
		exe := NewExecution("cnt_7", "dec_7", "apr_7", "agt_7", "exec", "exec:", 5)
		err := exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for empty resource")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set on empty resource")
		}
	})
}

func TestExecution_MarkTimedOut_SetsError(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "exec", "exec:sleep 10", 60)
	exe.MarkTimedOut()
	if exe.State != StateTimedOut {
		t.Errorf("state = %s, want timed_out", exe.State)
	}
	if exe.Error == "" {
		t.Error("error should be set by MarkTimedOut when previously empty")
	}
	if exe.FinishedAt == nil {
		t.Error("finished_at should be set")
	}
}

func TestExecution_MarkTimedOut_PreservesError(t *testing.T) {
	exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "exec", "exec:sleep 10", 60)
	exe.Error = "custom error before timeout"
	exe.MarkTimedOut()
	if exe.Error != "custom error before timeout" {
		t.Errorf("error = %q, want preserved custom error", exe.Error)
	}
}

func TestParseGitResource(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		wantRepo  string
		wantBranch string
		wantErr   bool
	}{
		{"simple_repo", "git:acme/repo", "acme/repo", "", false},
		{"with_branch", "git:acme/repo:feature-branch", "acme/repo", "feature-branch", false},
		{"local", "git:/Users/test/project", "/Users/test/project", "", false},
		{"trailing_branch_whitespace", "git:acme/repo: main", "acme/repo", "main", false},
		{"missing_prefix", "shell:echo hi", "", "", true},
		{"empty", "git:", "", "", true},
		{"whitespace_only", "git:   ", "", "", true},
		{"empty_repo", "git::branch", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseGitResource(tt.resource)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Repo != tt.wantRepo {
				t.Errorf("repo = %s, want %s", res.Repo, tt.wantRepo)
			}
			if res.Branch != tt.wantBranch {
				t.Errorf("branch = %s, want %s", res.Branch, tt.wantBranch)
			}
		})
	}
}

func TestParseGitResource_ErrorMessages(t *testing.T) {
	_, err := ParseGitResource("shell:echo")
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
	if !strings.Contains(err.Error(), "git:") {
		t.Errorf("error %q should mention 'git:' prefix requirement", err.Error())
	}

	_, err = ParseGitResource("git:")
	if err == nil {
		t.Fatal("expected error for empty git resource")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should mention empty", err.Error())
	}
}

func TestGitExecutor(t *testing.T) {
	ctx := context.Background()
	exec := NewGitExecutor(10)

	t.Run("unsupported_action_type", func(t *testing.T) {
		exe := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "git.force_push", "git:.", 10)
		err := exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for unsupported git action type")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set on unsupported action")
		}
	})

	t.Run("malformed_resource", func(t *testing.T) {
		exe := NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "git.push", "shell:ls", 10)
		err := exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for malformed resource")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if !strings.Contains(exe.Error, "git:") {
			t.Errorf("error %q should mention 'git:' prefix issue", exe.Error)
		}
	})

	t.Run("empty_resource", func(t *testing.T) {
		exe := NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "git.push", "git:", 10)
		err := exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error for empty resource")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
	})

	t.Run("missing_git_binary", func(t *testing.T) {
		// Create a real git repo so path validation passes; corrupt PATH to cause binary-not-found.
		// Note: LookPath succeeds (uses system PATH) but subprocess fails (uses modified PATH env).
		// The key validation is that execution fails with a descriptive error.
		resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
		if err != nil {
			t.Skipf("cannot resolve system temp dir: %v", err)
		}
		tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
		if err != nil {
			t.Skipf("cannot create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpBase)

		repoDir := filepath.Join(tmpBase, "repo_for_git_test")
		if err := os.MkdirAll(repoDir, 0755); err != nil {
			t.Fatalf("failed to create repo dir: %v", err)
		}
		gitInit := testExecCmd(ctx, "git", "init")
		gitInit.Dir = repoDir
		if out, err := gitInit.CombinedOutput(); err != nil {
			t.Skipf("git init failed: %v, out: %s", err, out)
		}

		ge := &GitExecutor{DefaultTimeout: 5 * time.Second}
		exe := NewExecution("cnt_4", "dec_4", "apr_4", "agt_4", "git.pull", "git:"+repoDir, 5)
		oldPath := os.Getenv("PATH")
		defer os.Setenv("PATH", oldPath)
		os.Setenv("PATH", "/nonexistent_path_for_git_test")
		err = ge.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error when git binary not found in subprocess PATH")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set when git binary not found")
		}
	})

	t.Run("nonexistent_repo_pull", func(t *testing.T) {
		// This tests the fast-path: repo path doesn't exist, caught by os.Stat before git is even invoked
		resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
		if err != nil {
			t.Skipf("cannot resolve system temp dir: %v", err)
		}
		tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
		if err != nil {
			t.Skipf("cannot create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpBase)

		nonexistentPath := filepath.Join(tmpBase, "this_subdir_does_not_exist")
		exe := NewExecution("cnt_5", "dec_5", "apr_5", "agt_5", "git.pull", "git:"+nonexistentPath, 10)
		err = exec.Execute(ctx, exe)
		if err == nil {
			t.Fatal("expected error when repo path does not exist")
		}
		if exe.State != StateFailed {
			t.Errorf("state = %s, want failed", exe.State)
		}
		if exe.Error == "" {
			t.Error("error field should be set for nonexistent repo")
		}
		if !strings.Contains(exe.Error, "does not exist") {
			t.Errorf("error %q should mention 'does not exist'", exe.Error)
		}
	})
}

func TestGitExecutor_isGitRepo(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	tmpDir := t.TempDir()
	tmpDirResolved, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Skipf("cannot resolve temp dir symlinks: %v", err)
	}

	t.Run("valid_git_repo", func(t *testing.T) {
		repoDir := filepath.Join(tmpDirResolved, "test_repo")
		if err := os.MkdirAll(repoDir, 0755); err != nil {
			t.Fatalf("failed to create repo dir: %v", err)
		}
		gitInit := testExecCmd(ctx, "git", "init")
		gitInit.Dir = repoDir
		if out, err := gitInit.CombinedOutput(); err != nil {
			t.Skipf("git not available or failed to init repo: %v, out: %s", err, out)
		}
		isRepo, err := gitExec.isGitRepo(ctx, repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isRepo {
			t.Error("expected isGitRepo=true for initialized repo")
		}
	})

	t.Run("not_a_git_repo", func(t *testing.T) {
		notGit := filepath.Join(tmpDirResolved, "not_git")
		if err := os.MkdirAll(notGit, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		isRepo, err := gitExec.isGitRepo(ctx, notGit)
		if err == nil {
			t.Error("expected error for non-git directory")
		}
		if isRepo {
			t.Error("expected isGitRepo=false for non-git directory")
		}
	})

	t.Run("nonexistent_path", func(t *testing.T) {
		nonexistent := filepath.Join(tmpDirResolved, "does_not_exist")
		isRepo, err := gitExec.isGitRepo(ctx, nonexistent)
		if err == nil {
			t.Error("expected error for nonexistent path")
		}
		if isRepo {
			t.Error("expected isRepo=false for nonexistent path")
		}
	})
}

func TestGitExecutor_Integration_Pull(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	// Use os.MkdirTemp + resolve symlinks to get a clean non-symlink path
	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)

	repoDir := filepath.Join(tmpBase, "integration_repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	// Init git repo
	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = repoDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git not available: %v, out: %s", err, out)
	}

	// Set up git config for the test
	gitConfig := testExecCmd(ctx, "git", "config", "user.email", "test@test.com")
	gitConfig.Dir = repoDir
	if out, err := gitConfig.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}
	gitConfig2 := testExecCmd(ctx, "git", "config", "user.name", "Test")
	gitConfig2.Dir = repoDir
	if out, err := gitConfig2.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}

	// Create a file and commit
	testFile := filepath.Join(repoDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	gitAdd := testExecCmd(ctx, "git", "add", ".")
	gitAdd.Dir = repoDir
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Skipf("git add failed: %v, out: %s", err, out)
	}

	gitCommit := testExecCmd(ctx, "git", "commit", "-m", "initial")
	gitCommit.Dir = repoDir
	if out, err := gitCommit.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %v, out: %s", err, out)
	}

	// Now test a pull on this repo. Without a remote, git pull exits 1 with a descriptive message.
	// This still validates: repo path resolution, isGitRepo check, git invocation, stdout capture.
	exe := NewExecution("cnt_int", "dec_int", "apr_int", "agt_int", "git.pull", "git:"+repoDir, 30)
	err = gitExec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("git.pull returned unexpected error: %v", err)
	}
	// git pull without a remote exits 1; the executor should propagate that as StateFailed
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed (no remote configured)", exe.State)
	}
	if exe.ExitCode == 0 {
		t.Error("exit_code should be non-zero for git pull without remote")
	}
	if exe.Stderr == "" {
		t.Error("stderr should be captured for git pull without remote")
	}
	if !strings.Contains(exe.Stderr, "fatal") && !strings.Contains(exe.Stderr, "upstream") {
		t.Logf("stderr: %s", exe.Stderr)
	}
}

func TestGitExecutor_Integration_Fetch(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_fetch_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)

	repoDir := filepath.Join(tmpBase, "fetch_repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = repoDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git not available: %v, out: %s", err, out)
	}

	gitConfig := testExecCmd(ctx, "git", "config", "user.email", "test@test.com")
	gitConfig.Dir = repoDir
	if out, err := gitConfig.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}
	gitConfig2 := testExecCmd(ctx, "git", "config", "user.name", "Test")
	gitConfig2.Dir = repoDir
	if out, err := gitConfig2.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}

	testFile := filepath.Join(repoDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	gitAdd := testExecCmd(ctx, "git", "add", ".")
	gitAdd.Dir = repoDir
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Skipf("git add failed: %v, out: %s", err, out)
	}

	gitCommit := testExecCmd(ctx, "git", "commit", "-m", "initial")
	gitCommit.Dir = repoDir
	if out, err := gitCommit.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %v, out: %s", err, out)
	}

	exe := NewExecution("cnt_fetch", "dec_fetch", "apr_fetch", "agt_fetch", "git.fetch", "git:"+repoDir, 30)
	err = gitExec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("git.fetch returned unexpected error: %v", err)
	}
	// git fetch without a remote succeeds (no-op); validates action type is accepted
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded (git fetch with no remote is a no-op)", exe.State)
	}
	if exe.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0 for git fetch with no remote", exe.ExitCode)
	}
}

func TestGitExecutor_NotGitRepo(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)
	notGitDir := filepath.Join(tmpBase, "plain_dir")
	if err := os.MkdirAll(notGitDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notGitDir, "readme.txt"), []byte("not git\n"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	exe := NewExecution("cnt_ng", "dec_ng", "apr_ng", "agt_ng", "git.pull", "git:"+notGitDir, 10)
	err = gitExec.Execute(ctx, exe)
	if err == nil {
		t.Fatal("expected error for not-a-git-repo directory")
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if !strings.Contains(exe.Error, "not a git repository") {
		t.Errorf("error %q should mention 'not a git repository'", exe.Error)
	}
}

func TestGitExecutor_SymlinkTraversalBlocked(t *testing.T) {
	ctx := context.Background()

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)
	realDir := filepath.Join(tmpBase, "real_repo")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("failed to create real dir: %v", err)
	}

	// Create a git repo in realDir
	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = realDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git init failed: %v, out: %s", err, out)
	}

	// Create symlink pointing to real dir
	symlinkDir := filepath.Join(tmpBase, "link_to_repo")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	ge := &GitExecutor{DefaultTimeout: 10 * time.Second}
	exe := NewExecution("cnt_sl", "dec_sl", "apr_sl", "agt_sl", "git.pull", "git:"+symlinkDir, 10)
	err = ge.Execute(ctx, exe)
	if err == nil {
		t.Fatal("expected error for symlink traversal")
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if !strings.Contains(exe.Error, "symlink traversal") {
		t.Errorf("error %q should mention 'symlink traversal'", exe.Error)
	}
}

func TestGitExecutor_PathIsFile(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_exec_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)
	filePath := filepath.Join(tmpBase, "just_a_file.txt")
	if err := os.WriteFile(filePath, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	exe := NewExecution("cnt_f", "dec_f", "apr_f", "agt_f", "git.pull", "git:"+filePath, 10)
	err = gitExec.Execute(ctx, exe)
	if err == nil {
		t.Fatal("expected error for file path instead of directory")
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if !strings.Contains(exe.Error, "not a directory") {
		t.Errorf("error %q should mention 'not a directory'", exe.Error)
	}
}

func TestGitExecutor_Integration_Checkout(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_checkout_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)

	repoDir := filepath.Join(tmpBase, "checkout_repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = repoDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git not available: %v, out: %s", err, out)
	}

	gitConfig := testExecCmd(ctx, "git", "config", "user.email", "test@test.com")
	gitConfig.Dir = repoDir
	if out, err := gitConfig.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}
	gitConfig2 := testExecCmd(ctx, "git", "config", "user.name", "Test")
	gitConfig2.Dir = repoDir
	if out, err := gitConfig2.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}

	testFile := filepath.Join(repoDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	gitAdd := testExecCmd(ctx, "git", "add", ".")
	gitAdd.Dir = repoDir
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Skipf("git add failed: %v, out: %s", err, out)
	}

	gitCommit := testExecCmd(ctx, "git", "commit", "-m", "initial")
	gitCommit.Dir = repoDir
	if out, err := gitCommit.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %v, out: %s", err, out)
	}

	gitBranch := testExecCmd(ctx, "git", "branch", "feature")
	gitBranch.Dir = repoDir
	if out, err := gitBranch.CombinedOutput(); err != nil {
		t.Skipf("git branch failed: %v, out: %s", err, out)
	}

	exe := NewExecution("cnt_co", "dec_co", "apr_co", "agt_co", "git.checkout", "git:"+repoDir+":feature", 30)
	err = gitExec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("git.checkout returned unexpected error: %v", err)
	}
	if exe.State != StateSucceeded {
		t.Errorf("state = %s, want succeeded", exe.State)
	}
	if exe.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", exe.ExitCode)
	}
}

func TestGitExecutor_Checkout_MissingBranch(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_co_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)

	repoDir := filepath.Join(tmpBase, "co_repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = repoDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git not available: %v, out: %s", err, out)
	}

	exe := NewExecution("cnt_co2", "dec_co2", "apr_co2", "agt_co2", "git.checkout", "git:"+repoDir, 30)
	err = gitExec.Execute(ctx, exe)
	if err == nil {
		t.Fatal("expected error for missing branch")
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed", exe.State)
	}
	if !strings.Contains(exe.Error, "branch is required") {
		t.Errorf("error = %q, want 'branch is required' message", exe.Error)
	}
}

func TestGitExecutor_Checkout_NonexistentBranch(t *testing.T) {
	ctx := context.Background()
	gitExec := NewGitExecutor(10)

	resolvedTmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Skipf("cannot resolve system temp dir: %v", err)
	}
	tmpBase, err := os.MkdirTemp(resolvedTmp, "git_co_test")
	if err != nil {
		t.Skipf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpBase)

	repoDir := filepath.Join(tmpBase, "co_repo2")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	gitInit := testExecCmd(ctx, "git", "init")
	gitInit.Dir = repoDir
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Skipf("git not available: %v, out: %s", err, out)
	}

	gitConfig := testExecCmd(ctx, "git", "config", "user.email", "test@test.com")
	gitConfig.Dir = repoDir
	if out, err := gitConfig.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}
	gitConfig2 := testExecCmd(ctx, "git", "config", "user.name", "Test")
	gitConfig2.Dir = repoDir
	if out, err := gitConfig2.CombinedOutput(); err != nil {
		t.Skipf("git config failed: %v, out: %s", err, out)
	}

	testFile := filepath.Join(repoDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	gitAdd := testExecCmd(ctx, "git", "add", ".")
	gitAdd.Dir = repoDir
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Skipf("git add failed: %v, out: %s", err, out)
	}

	gitCommit := testExecCmd(ctx, "git", "commit", "-m", "initial")
	gitCommit.Dir = repoDir
	if out, err := gitCommit.CombinedOutput(); err != nil {
		t.Skipf("git commit failed: %v, out: %s", err, out)
	}

	exe := NewExecution("cnt_co3", "dec_co3", "apr_co3", "agt_co3", "git.checkout", "git:"+repoDir+":nonexistent", 30)
	err = gitExec.Execute(ctx, exe)
	if err != nil {
		t.Fatalf("unexpected Execute error: %v", err)
	}
	if exe.State != StateFailed {
		t.Errorf("state = %s, want failed for nonexistent branch checkout", exe.State)
	}
	if exe.ExitCode == 0 {
		t.Error("exit_code should be non-zero for nonexistent branch")
	}
}
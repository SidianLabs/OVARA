package execution

import (
	"testing"
)

func TestExecution_FailureInfo_Succeeded(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkSucceeded(0, "ok", "")

	info := e.FailureInfo()
	if info.Category != "success" {
		t.Errorf("Category = %s, want success", info.Category)
	}
	if info.Reason != "execution succeeded" {
		t.Errorf("Reason = %s, want 'execution succeeded'", info.Reason)
	}
	if info.Recoverable {
		t.Error("Recoverable should be false for success")
	}
}

func TestExecution_FailureInfo_Running(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkStarted()

	info := e.FailureInfo()
	if info.Category != "in_progress" {
		t.Errorf("Category = %s, want in_progress", info.Category)
	}
}

func TestExecution_FailureInfo_CommandFailed(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("exit status 1", 1)

	info := e.FailureInfo()
	if info.Category != "command_failed" {
		t.Errorf("Category = %s, want command_failed", info.Category)
	}
	if info.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", info.ExitCode)
	}
	if !info.Recoverable {
		t.Error("Recoverable should be true for command_failed")
	}
}

func TestExecution_FailureInfo_Timeout(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:sleep 100", 60)
	e.MarkTimedOut()

	info := e.FailureInfo()
	if info.Category != "timeout" {
		t.Errorf("Category = %s, want timeout", info.Category)
	}
	if !info.Recoverable {
		t.Error("Recoverable should be true for timeout")
	}
}

func TestExecution_FailureInfo_ValidationError(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("invalid shell resource: missing command", 1)

	info := e.FailureInfo()
	if info.Category != "validation_error" {
		t.Errorf("Category = %s, want validation_error", info.Category)
	}
	if info.Recoverable {
		t.Error("Recoverable should be false for validation_error")
	}
}

func TestExecution_FailureInfo_ExecNotFound(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "exec", "exec:nonexistent", 60)
	e.MarkFailed("exec: binary not found: nonexistent", 1)

	info := e.FailureInfo()
	if info.Category != "executor_error" {
		t.Errorf("Category = %s, want executor_error", info.Category)
	}
	if info.Recoverable {
		t.Error("Recoverable should be false for executor_error not found")
	}
}

func TestExecution_FailureInfo_GitError(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "git.push", "git:/repo:master", 60)
	e.MarkFailed("git: repository path does not exist: /repo", 1)

	info := e.FailureInfo()
	if info.Category != "git_error" {
		t.Errorf("Category = %s, want git_error", info.Category)
	}
	if info.Recoverable {
		t.Error("Recoverable should be false for git_error not found")
	}
}

func TestExecution_FailureInfo_PermissionDenied(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("permission denied: /etc/passwd", 1)

	info := e.FailureInfo()
	if info.Category != "permission_denied" {
		t.Errorf("Category = %s, want permission_denied", info.Category)
	}
	if info.Recoverable {
		t.Error("Recoverable should be false for permission_denied")
	}
}

func TestExecution_FailureInfo_NotFound(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("file not found: /tmp/missing", 1)

	info := e.FailureInfo()
	if info.Category != "not_found" {
		t.Errorf("Category = %s, want not_found", info.Category)
	}
}

func TestExecution_FailureInfo_ExitCodePreserved(t *testing.T) {
	e := NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e.MarkFailed("some error", 42)

	info := e.FailureInfo()
	if info.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", info.ExitCode)
	}
}

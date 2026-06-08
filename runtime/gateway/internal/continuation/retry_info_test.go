package continuation

import (
	"testing"
)

func TestContinuation_RetryInfo_Retryable(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 1

	info := c.RetryInfo()
	if !info.CanRetry {
		t.Error("CanRetry should be true")
	}
	if info.RetryLimitReached {
		t.Error("RetryLimitReached should be false")
	}
	if info.RetriesRemaining != 2 {
		t.Errorf("RetriesRemaining = %d, want 2", info.RetriesRemaining)
	}
	if info.Status != "retryable" {
		t.Errorf("Status = %s, want retryable", info.Status)
	}
}

func TestContinuation_RetryInfo_Exhausted(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 3

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if !info.RetryLimitReached {
		t.Error("RetryLimitReached should be true")
	}
	if info.RetriesRemaining != 0 {
		t.Errorf("RetriesRemaining = %d, want 0", info.RetriesRemaining)
	}
	if info.Status != "exhausted" {
		t.Errorf("Status = %s, want exhausted", info.Status)
	}
}

func TestContinuation_RetryInfo_MaxRetriesZero(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 0
	c.RetryCount = 0

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "disabled" {
		t.Errorf("Status = %s, want disabled", info.Status)
	}
}

func TestContinuation_RetryInfo_TerminalState_Denied(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateDenied

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "terminal" {
		t.Errorf("Status = %s, want terminal", info.Status)
	}
}

func TestContinuation_RetryInfo_TerminalState_Expired(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExpired

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "terminal" {
		t.Errorf("Status = %s, want terminal", info.Status)
	}
}

func TestContinuation_RetryInfo_TerminalState_Cancelled(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateCancelled

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "terminal" {
		t.Errorf("Status = %s, want terminal", info.Status)
	}
}

func TestContinuation_RetryInfo_NotExecutedYet(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "not_needed" {
		t.Errorf("Status = %s, want not_needed", info.Status)
	}
}

func TestContinuation_RetryInfo_PendingApproval(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	// State remains StateEscalated

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "pending_approval" {
		t.Errorf("Status = %s, want pending_approval", info.Status)
	}
}

func TestContinuation_RetryInfo_FromResumed(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateResumed
	c.MaxRetries = 3
	c.RetryCount = 2

	info := c.RetryInfo()
	if !info.CanRetry {
		t.Error("CanRetry should be true")
	}
	if info.Status != "retryable" {
		t.Errorf("Status = %s, want retryable", info.Status)
	}
	if info.RetriesRemaining != 1 {
		t.Errorf("RetriesRemaining = %d, want 1", info.RetriesRemaining)
	}
}

func TestContinuation_RetryInfo_QueuedState(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkQueued()

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false")
	}
	if info.Status != "not_needed" {
		t.Errorf("Status = %s, want not_needed", info.Status)
	}
}

func TestContinuation_RetryInfo_Executing(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuting
	c.MaxRetries = 3
	c.RetryCount = 0

	info := c.RetryInfo()
	if info.CanRetry {
		t.Error("CanRetry should be false for executing")
	}
	if info.Status != "in_progress" {
		t.Errorf("Status = %s, want in_progress", info.Status)
	}
	if info.RetriesRemaining != 3 {
		t.Errorf("RetriesRemaining = %d, want 3", info.RetriesRemaining)
	}
}

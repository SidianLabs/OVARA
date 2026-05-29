package continuation

import (
	"testing"
)

func TestContinuation_Retry_FromExecuted(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 0

	ok := c.Retry()
	if !ok {
		t.Error("expected Retry() to succeed from executed state")
	}
	if c.State != StateResumed {
		t.Errorf("state = %v, want resumed", c.State)
	}
	if c.RetryCount != 1 {
		t.Errorf("retry_count = %v, want 1", c.RetryCount)
	}
}

func TestContinuation_Retry_FromResumed(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateResumed
	c.MaxRetries = 3
	c.RetryCount = 1

	ok := c.Retry()
	if !ok {
		t.Error("expected Retry() to succeed from resumed state")
	}
	if c.State != StateResumed {
		t.Errorf("state = %v, want resumed", c.State)
	}
	if c.RetryCount != 2 {
		t.Errorf("retry_count = %v, want 2", c.RetryCount)
	}
}

func TestContinuation_Retry_InvalidState_Approved(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail from approved state")
	}
}

func TestContinuation_Retry_InvalidState_Escalated(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail from escalated state")
	}
}

func TestContinuation_Retry_InvalidState_Denied(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateDenied

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail from denied state")
	}
}

func TestContinuation_Retry_InvalidState_Expired(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExpired

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail from expired state")
	}
}

func TestContinuation_Retry_InvalidState_Cancelled(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateCancelled

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail from cancelled state")
	}
}

func TestContinuation_Retry_MaxRetriesZero(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 0
	c.RetryCount = 0

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail when max_retries is 0")
	}
}

func TestContinuation_Retry_MaxRetriesReached(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 3

	ok := c.Retry()
	if ok {
		t.Error("expected Retry() to fail when retry_count >= max_retries")
	}
}

func TestContinuation_Retry_SetsResumedAt(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.State = StateExecuted
	c.MaxRetries = 3
	c.RetryCount = 0

	c.Retry()

	if c.ResumedAt == nil {
		t.Error("ResumedAt should be set after Retry()")
	}
}

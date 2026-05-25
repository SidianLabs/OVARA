package execution

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateTimedOut  State = "timed_out"
)

type Execution struct {
	ExecutionID     string    `json:"execution_id"`
	ContinuationID string    `json:"continuation_id"`
	DecisionID     string    `json:"decision_id,omitempty"`
	ApprovalID     string    `json:"approval_id,omitempty"`
	AgentID        string    `json:"agent_id,omitempty"`
	ActionType     string    `json:"action_type"`
	Resource       string    `json:"resource"`
	State          State     `json:"state"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	ExitCode       int       `json:"exit_code,omitempty"`
	Stdout         string    `json:"stdout,omitempty"`
	Stderr         string    `json:"stderr,omitempty"`
	StdoutTruncated bool     `json:"stdout_truncated,omitempty"`
	StderrTruncated bool     `json:"stderr_truncated,omitempty"`
	StdoutLimitBytes int     `json:"stdout_limit_bytes,omitempty"`
	StderrLimitBytes int     `json:"stderr_limit_bytes,omitempty"`
	Error          string    `json:"error,omitempty"`
	TimeoutSeconds int       `json:"timeout_seconds"`
}

func NewExecution(continuationID, decisionID, approvalID, agentID, actionType, resource string, timeoutSec int) *Execution {
	return &Execution{
		ExecutionID:    "exe_" + uuid.New().String()[:16],
		ContinuationID: continuationID,
		DecisionID:     decisionID,
		ApprovalID:     approvalID,
		AgentID:        agentID,
		ActionType:     actionType,
		Resource:       resource,
		State:          StatePending,
		TimeoutSeconds: timeoutSec,
	}
}

func (e *Execution) MarkStarted() {
	e.State = StateRunning
	e.StartedAt = time.Now().UTC()
}

func (e *Execution) MarkSucceeded(exitCode int, stdout, stderr string) {
	e.State = StateSucceeded
	e.ExitCode = exitCode
	e.Stdout = stdout
	e.Stderr = stderr
	now := time.Now().UTC()
	e.FinishedAt = &now
}

func (e *Execution) MarkFailed(errMsg string, exitCode int) {
	e.State = StateFailed
	e.Error = errMsg
	e.ExitCode = exitCode
	now := time.Now().UTC()
	e.FinishedAt = &now
}

func (e *Execution) IsTerminal() bool {
	return e.State == StateSucceeded || e.State == StateFailed || e.State == StateTimedOut
}

func (e *Execution) MarkTimedOut() {
	e.State = StateTimedOut
	now := time.Now().UTC()
	e.FinishedAt = &now
}

type Executor interface {
	Execute(ctx context.Context, e *Execution) error
}

type ShellExecutor struct {
	DefaultTimeout    time.Duration
	StdoutLimitBytes int
	StderrLimitBytes int
	WorkingDir       string
	AllowedEnvVars   []string
}

func NewShellExecutor(timeoutSec int) *ShellExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	return &ShellExecutor{
		DefaultTimeout:    time.Duration(timeoutSec) * time.Second,
		StdoutLimitBytes: 1024 * 1024,   // 1 MB default
		StderrLimitBytes: 256 * 1024,    // 256 KB default
	}
}

func NewShellExecutorWithLimits(timeoutSec, stdoutLimit, stderrLimit int) *ShellExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	if stdoutLimit <= 0 {
		stdoutLimit = 1024 * 1024
	}
	if stderrLimit <= 0 {
		stderrLimit = 256 * 1024
	}
	return &ShellExecutor{
		DefaultTimeout:    time.Duration(timeoutSec) * time.Second,
		StdoutLimitBytes: stdoutLimit,
		StderrLimitBytes: stderrLimit,
	}
}

func (se *ShellExecutor) Execute(ctx context.Context, e *Execution) error {
	e.MarkStarted()

	shellCmd, err := ParseShellResource(e.Resource)
	if err != nil {
		e.MarkFailed("invalid shell resource: "+err.Error(), 1)
		return err
	}

	timeout := se.DefaultTimeout
	if e.TimeoutSeconds > 0 {
		timeout = time.Duration(e.TimeoutSeconds) * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdoutBuf := &limitedWriter{buf: new(bytes.Buffer), limit: se.StdoutLimitBytes}
	stderrBuf := &limitedWriter{buf: new(bytes.Buffer), limit: se.StderrLimitBytes}

	cmd := exec.CommandContext(execCtx, "sh", "-c", shellCmd)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if se.WorkingDir != "" {
		cmd.Dir = se.WorkingDir
	}
	if se.AllowedEnvVars != nil {
		cmd.Env = filterEnv(se.AllowedEnvVars)
	}

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		if execCtx.Err() == context.DeadlineExceeded {
			e.MarkTimedOut()
			e.Stdout = stdoutBuf.buf.String()
			e.Stderr = stderrBuf.buf.String()
			e.StdoutTruncated = stdoutBuf.truncated
			e.StderrTruncated = stderrBuf.truncated
			e.StdoutLimitBytes = se.StdoutLimitBytes
			e.StderrLimitBytes = se.StderrLimitBytes
			return err
		}
		e.MarkFailed(stderrBuf.buf.String(), exitCode)
		e.Stdout = stdoutBuf.buf.String()
		e.Stderr = stderrBuf.buf.String()
		e.StdoutTruncated = stdoutBuf.truncated
		e.StderrTruncated = stderrBuf.truncated
		e.StdoutLimitBytes = se.StdoutLimitBytes
		e.StderrLimitBytes = se.StderrLimitBytes
		return nil
	}

	e.MarkSucceeded(exitCode, stdoutBuf.buf.String(), stderrBuf.buf.String())
	e.StdoutTruncated = stdoutBuf.truncated
	e.StderrTruncated = stderrBuf.truncated
	e.StdoutLimitBytes = se.StdoutLimitBytes
	e.StderrLimitBytes = se.StderrLimitBytes
	return nil
}

type limitedWriter struct {
	buf       *bytes.Buffer
	limit     int
	truncated bool
}

func (lw *limitedWriter) Write(p []byte) (n int, err error) {
	if lw.buf.Len()+len(p) > lw.limit {
		remaining := lw.limit - lw.buf.Len()
		if remaining > 0 {
			lw.buf.Write(p[:remaining])
		}
		lw.truncated = true
		return len(p), nil
	}
	return lw.buf.Write(p)
}

func filterEnv(allowed []string) []string {
	env := []string{}
	for _, key := range allowed {
		if val, ok := getEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}

func getEnv(key string) (string, bool) {
	for _, e := range os.Environ() {
		if len(e) > len(key) && e[:len(key)+1] == key+"=" {
			return e[len(key)+1:], true
		}
	}
	return "", false
}

func ParseShellResource(resource string) (string, error) {
	if !strings.HasPrefix(resource, "shell:") {
		return "", fmt.Errorf("resource does not start with shell: %s", resource)
	}
	cmd := strings.TrimPrefix(resource, "shell:")
	if cmd == "" {
		return "", fmt.Errorf("shell command is empty")
	}
	return cmd, nil
}

type Store interface {
	Create(e *Execution) error
	Get(id string) (*Execution, bool)
	Update(e *Execution) error
	ListByContinuation(continuationID string) []*Execution
	ListAll() []*Execution
	ListByState(state State) []*Execution
	Stats() (total, succeeded, failed, running, timedOut int)
}

type InMemoryStore struct {
	executions map[string]*Execution
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		executions: make(map[string]*Execution),
	}
}

func (s *InMemoryStore) Create(e *Execution) error {
	if _, exists := s.executions[e.ExecutionID]; exists {
		return fmt.Errorf("execution already exists: %s", e.ExecutionID)
	}
	s.executions[e.ExecutionID] = e
	return nil
}

func (s *InMemoryStore) Get(id string) (*Execution, bool) {
	e, ok := s.executions[id]
	return e, ok
}

func (s *InMemoryStore) Update(e *Execution) error {
	if _, exists := s.executions[e.ExecutionID]; !exists {
		return fmt.Errorf("execution not found: %s", e.ExecutionID)
	}
	s.executions[e.ExecutionID] = e
	return nil
}

func (s *InMemoryStore) ListByContinuation(continuationID string) []*Execution {
	var result []*Execution
	for _, e := range s.executions {
		if e.ContinuationID == continuationID {
			result = append(result, e)
		}
	}
	return result
}

func (s *InMemoryStore) ListAll() []*Execution {
	var result []*Execution
	for _, e := range s.executions {
		result = append(result, e)
	}
	return result
}

func (s *InMemoryStore) ListByState(state State) []*Execution {
	var result []*Execution
	for _, e := range s.executions {
		if e.State == state {
			result = append(result, e)
		}
	}
	return result
}

func (s *InMemoryStore) Stats() (total, succeeded, failed, running, timedOut int) {
	for _, e := range s.executions {
		total++
		switch e.State {
		case StateSucceeded:
			succeeded++
		case StateFailed:
			failed++
		case StateRunning:
			running++
		case StateTimedOut:
			timedOut++
		}
	}
	return
}
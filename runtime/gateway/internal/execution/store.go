package execution

import (
	"bytes"
	"context"
	"fmt"
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
	ExecutionID    string    `json:"execution_id"`
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

func (e *Execution) MarkFailed(errMsg string) {
	e.State = StateFailed
	e.Error = errMsg
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
	DefaultTimeout time.Duration
}

func NewShellExecutor(timeoutSec int) *ShellExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	return &ShellExecutor{
		DefaultTimeout: time.Duration(timeoutSec) * time.Second,
	}
}

func (se *ShellExecutor) Execute(ctx context.Context, e *Execution) error {
	e.MarkStarted()

	shellCmd, err := ParseShellResource(e.Resource)
	if err != nil {
		e.MarkFailed("invalid shell resource: " + err.Error())
		return err
	}

	execCtx, cancel := context.WithTimeout(ctx, se.DefaultTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(execCtx, "sh", "-c", shellCmd)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		if execCtx.Err() == context.DeadlineExceeded {
			e.MarkTimedOut()
			return err
		}
		e.MarkFailed(stderr.String())
		return nil
	}

	e.MarkSucceeded(exitCode, stdout.String(), stderr.String())
	return nil
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
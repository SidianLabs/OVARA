package continuation

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type State string

const (
	StateEscalated  State = "escalated"
	StateApproved   State = "approved"
	StateQueued     State = "queued"
	StateExecuting  State = "executing" // claimed and actively running; never a resting state
	StateDenied     State = "denied"
	StateResumed    State = "resumed"
	StateExpired    State = "expired"
	StateExecuted   State = "executed"
	StateCancelled  State = "cancelled"
)

const DefaultExpirationMinutes = 60

type Continuation struct {
	ContinuationID string    `json:"continuation_id"`
	DecisionID    string    `json:"decision_id"`
	ApprovalID    string    `json:"approval_id,omitempty"`
	AgentID       string    `json:"agent_id,omitempty"`
	ActionType    string    `json:"action_type"`
	Resource      string    `json:"resource"`
	Environment   string    `json:"environment,omitempty"`
	State         State     `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	QueuedAt      *time.Time `json:"queued_at,omitempty"`
	ResumedAt     *time.Time `json:"resumed_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ExpiredAt     *time.Time `json:"expired_at,omitempty"`
	CancelledAt   *time.Time `json:"cancelled_at,omitempty"`
	ResolvedBy    string    `json:"resolved_by,omitempty"`
	DenyReason    string    `json:"deny_reason,omitempty"`
	TrustScore    float64   `json:"trust_score,omitempty"`
	TrustLevel    string    `json:"trust_level,omitempty"`
	AnomalyCodes  []string  `json:"anomaly_codes,omitempty"`
	ShieldActive  bool      `json:"shield_active,omitempty"`
	Restricted    bool      `json:"restricted,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	CapabilityRef string    `json:"capability_ref,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	RetryCount    int       `json:"retry_count,omitempty"`
	MaxRetries    int       `json:"max_retries,omitempty"`
	LastSkippedAt *time.Time `json:"last_skipped_at,omitempty"`
}

// snapshot returns a shallow copy of the continuation. Store methods return a
// snapshot (taken while holding the store lock) so callers can read fields
// without racing concurrent mutations on the live stored object. Shared
// reference fields (AnomalyCodes, Metadata, time pointers) are intentionally
// shared — callers must treat the snapshot as read-only.
func (c *Continuation) snapshot() *Continuation {
	cp := *c
	return &cp
}

func (c *Continuation) CanResume() bool {
	return c.State == StateApproved
}

func (c *Continuation) IsTerminal() bool {
	return c.State == StateDenied || c.State == StateExpired || c.State == StateExecuted || c.State == StateCancelled
}

func NewContinuation(decisionID, actionType, resource string) *Continuation {
	return &Continuation{
		ContinuationID: "cnt_" + uuid.New().String()[:16],
		DecisionID:     decisionID,
		ActionType:     actionType,
		Resource:       resource,
		State:          StateEscalated,
		CreatedAt:      time.Now().UTC(),
		MaxRetries:     3,
		RetryCount:     0,
	}
}

func (c *Continuation) WithMaxRetries(max int) *Continuation {
	c.MaxRetries = max
	return c
}

func (c *Continuation) WithAgentID(agentID string) *Continuation {
	c.AgentID = agentID
	return c
}

func (c *Continuation) WithEnvironment(env string) *Continuation {
	c.Environment = env
	return c
}

func (c *Continuation) WithTrustContext(score float64, level string, anomalies []string, shieldActive, restricted bool) *Continuation {
	c.TrustScore = score
	c.TrustLevel = level
	c.AnomalyCodes = anomalies
	c.ShieldActive = shieldActive
	c.Restricted = restricted
	return c
}

func (c *Continuation) WithPolicyVersion(pv string) *Continuation {
	c.PolicyVersion = pv
	return c
}

func (c *Continuation) WithCapabilityRef(ref string) *Continuation {
	c.CapabilityRef = ref
	return c
}

func (c *Continuation) WithApprovalID(approvalID string) *Continuation {
	c.ApprovalID = approvalID
	return c
}

func (c *Continuation) WithExpiration(minutes int) *Continuation {
	if minutes > 0 {
		t := c.CreatedAt.Add(time.Duration(minutes) * time.Minute)
		c.ExpiresAt = &t
	}
	return c
}

func (c *Continuation) WithMetadata(key string, value any) *Continuation {
	if c.Metadata == nil {
		c.Metadata = make(map[string]any)
	}
	c.Metadata[key] = value
	return c
}

func (c *Continuation) MarkApproved(resolvedBy string) {
	if c.IsTerminal() {
		return
	}
	c.State = StateApproved
	c.ResolvedBy = resolvedBy
	now := time.Now().UTC()
	c.ApprovedAt = &now
}

// MarkQueued transitions an approved continuation into the queued state
// so the orchestrator can pick it up for execution.
func (c *Continuation) MarkQueued() {
	if c.State == StateApproved {
		c.State = StateQueued
		now := time.Now().UTC()
		c.QueuedAt = &now
	}
}

func (c *Continuation) MarkDenied(resolvedBy, reason string) {
	if c.IsTerminal() {
		return
	}
	c.State = StateDenied
	c.ResolvedBy = resolvedBy
	c.DenyReason = reason
}

func (c *Continuation) MarkResumed() {
	if c.IsTerminal() {
		return
	}
	c.State = StateResumed
	now := time.Now().UTC()
	c.ResumedAt = &now
}

func (c *Continuation) Retry() bool {
	if c.State != StateExecuted && c.State != StateResumed {
		return false
	}
	if c.MaxRetries <= 0 {
		return false
	}
	if c.RetryCount >= c.MaxRetries {
		return false
	}
	c.State = StateResumed
	c.RetryCount++
	now := time.Now().UTC()
	c.ResumedAt = &now
	return true
}

func (c *Continuation) MarkExecuted() {
	if c.State != StateResumed && c.State != StateExecuting {
		return
	}
	c.State = StateExecuted
}

// MarkExecutionFailed transitions a claimed continuation back to StateExecuted
// so it can be retried. Called after a failed or timed-out execution.
func (c *Continuation) MarkExecutionFailed() {
	if c.State != StateExecuting {
		return
	}
	c.State = StateExecuted
}

// MarkRequeue returns a claimed (StateExecuting) continuation back to
// StateQueued so it can be picked up by the orchestrator again. Used by
// paths that successfully claimed a continuation but cannot execute it
// (e.g. unknown action type in the executor registry). Only requeues from
// transient claim states — never from terminal, approved, or escalated
// states.
func (c *Continuation) MarkRequeue() {
	if c.State == StateExecuting {
		c.State = StateQueued
		now := time.Now().UTC()
		c.QueuedAt = &now
	}
}

func (c *Continuation) MarkCancelled() {
	if c.State == StateQueued || c.State == StateResumed {
		c.State = StateCancelled
		now := time.Now().UTC()
		c.CancelledAt = &now
	}
}

func (c *Continuation) CanEnqueue() bool {
	return c.State == StateApproved
}

func (c *Continuation) CanCancel() bool {
	return c.State == StateQueued || c.State == StateResumed
}

func (c *Continuation) CanRetry() bool {
	if c.State != StateExecuted && c.State != StateResumed {
		return false
	}
	if c.MaxRetries <= 0 {
		return false
	}
	return c.RetryCount < c.MaxRetries
}

type RetryInfo struct {
	CanRetry         bool   `json:"can_retry"`
	RetryLimitReached bool   `json:"retry_limit_reached"`
	RetriesRemaining  int    `json:"retries_remaining"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
}

func (c *Continuation) RetryInfo() RetryInfo {
	info := RetryInfo{
		CanRetry:          c.CanRetry(),
		RetryLimitReached: false,
		RetriesRemaining:  0,
	}

	if c.MaxRetries > 0 {
		info.RetriesRemaining = c.MaxRetries - c.RetryCount
		if info.RetriesRemaining < 0 {
			info.RetriesRemaining = 0
		}
	}

	switch {
	case c.State == StateDenied || c.State == StateExpired || c.State == StateCancelled:
		info.Status = "terminal"
		info.Reason = "continuation is in terminal state: " + string(c.State)
	case c.State == StateExecuting:
		info.Status = "in_progress"
		info.Reason = "continuation is currently executing; retry only available after completion or failure"
	case c.State == StateExecuted || c.State == StateResumed:
		if c.MaxRetries <= 0 {
			info.Status = "disabled"
			info.Reason = "max_retries is 0, retry disabled"
		} else if c.RetryCount >= c.MaxRetries {
			info.Status = "exhausted"
			info.Reason = "retry limit reached (retry_count=" + strconv.Itoa(c.RetryCount) + ", max_retries=" + strconv.Itoa(c.MaxRetries) + ")"
			info.RetryLimitReached = true
		} else {
			info.Status = "retryable"
			info.Reason = "execution completed, retry available"
		}
	case c.State == StateApproved || c.State == StateQueued:
		info.Status = "not_needed"
		info.Reason = "continuation has not been executed yet"
	case c.State == StateEscalated:
		info.Status = "pending_approval"
		info.Reason = "continuation awaiting approval"
	default:
		info.Status = "unknown"
		info.Reason = "state: " + string(c.State)
	}

	return info
}

func (c *Continuation) MarkExpired() {
	if !c.IsTerminal() {
		c.State = StateExpired
		now := time.Now().UTC()
		c.ExpiredAt = &now
	}
}

// IsQueued returns true when the continuation has been queued for execution
// and is awaiting pickup by the orchestrator.
func (c *Continuation) IsQueued() bool {
	return c.State == StateQueued
}

func (c *Continuation) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*c.ExpiresAt)
}

func (c *Continuation) ShouldExpire(now time.Time) bool {
	if c.State != StateEscalated && c.State != StateApproved {
		return false
	}
	if c.ExpiresAt == nil {
		return false
	}
	return now.After(*c.ExpiresAt)
}

func (c *Continuation) IsExecutable() bool {
	if c.State != StateApproved && c.State != StateQueued {
		return false
	}
	// StateExecuting means already claimed by another path — not available
	if c.State == StateExecuted || c.State == StateCancelled || c.State == StateExecuting {
		return false
	}
	if c.ExpiresAt != nil && time.Now().UTC().After(*c.ExpiresAt) {
		return false
	}
	return true
}

func (c *Continuation) CanExecute() bool {
	// StateExecuting means already claimed; never allow a second claim
	if c.State == StateExecuting {
		return false
	}
	if c.State != StateQueued && c.State != StateResumed && c.State != StateApproved {
		return false
	}
	return true
}

func (c *Continuation) TimeToExpiry() time.Duration {
	if c.ExpiresAt == nil {
		return -1
	}
	return time.Until(*c.ExpiresAt)
}

type Store interface {
	Create(c *Continuation) error
	Get(id string) (*Continuation, bool)
	Update(c *Continuation) error
	ListByState(state State) []*Continuation
	ListByDecision(decisionID string) []*Continuation
	ListByAgent(agentID string) []*Continuation
	ListByApprovalID(approvalID string) []*Continuation
	ListAll() []*Continuation
	ListNonTerminal() []*Continuation
	ClaimForExecution(id string) (*Continuation, bool)
	ClaimForRetry(id string) (*Continuation, bool)
	RetryForExecution(id string) (*Continuation, bool)
	CancelForOperation(id string) (*Continuation, bool)
	RecoverFromExecuting(id string) (*Continuation, bool)
	ListExecutingIDs() []string
}

type InMemoryStore struct {
	mu           sync.RWMutex
	continuations map[string]*Continuation
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		continuations: make(map[string]*Continuation),
	}
}

func (s *InMemoryStore) Create(c *Continuation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.continuations[c.ContinuationID]; exists {
		return fmt.Errorf("continuation already exists: %s", c.ContinuationID)
	}
	s.continuations[c.ContinuationID] = c
	return nil
}

func (s *InMemoryStore) Get(id string) (*Continuation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	return c.snapshot(), true
}

func (s *InMemoryStore) Update(c *Continuation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.continuations[c.ContinuationID]; !exists {
		return fmt.Errorf("continuation not found: %s", c.ContinuationID)
	}
	s.continuations[c.ContinuationID] = c
	return nil
}

func (s *InMemoryStore) ListByState(state State) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.State == state {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *InMemoryStore) ListByDecision(decisionID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.DecisionID == decisionID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *InMemoryStore) ListByAgent(agentID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.AgentID == agentID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *InMemoryStore) ListByApprovalID(approvalID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.ApprovalID == approvalID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *InMemoryStore) ListAll() []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		result = append(result, c.snapshot())
	}
	return result
}

func (s *InMemoryStore) ListNonTerminal() []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if !c.IsTerminal() {
			result = append(result, c)
		}
	}
	return result
}

func (s *InMemoryStore) ClaimForExecution(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State == StateApproved || c.State == StateQueued || c.State == StateResumed {
		c.State = StateExecuting
		return c.snapshot(), true
	}
	return nil, false
}

func (s *InMemoryStore) ClaimForRetry(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State == StateResumed {
		c.State = StateExecuting
		return c.snapshot(), true
	}
	return nil, false
}
func (s *InMemoryStore) RetryForExecution(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State != StateExecuted && c.State != StateResumed {
		return nil, false
	}
	if c.MaxRetries <= 0 {
		return nil, false
	}
	if c.RetryCount >= c.MaxRetries {
		return nil, false
	}
	c.State = StateResumed
	c.RetryCount++
	now := time.Now().UTC()
	c.ResumedAt = &now
	return c.snapshot(), true
}

// CancelForOperation atomically cancels a cancellable continuation under the
// store lock and returns a snapshot. Centralizing the CanCancel check and the
// MarkCancelled mutation here prevents concurrent cancel callers (single vs
// bulk) from racing on the shared continuation object.
func (s *InMemoryStore) CancelForOperation(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if !c.CanCancel() {
		return nil, false
	}
	c.MarkCancelled()
	return c.snapshot(), true
}

// RecoverFromExecuting atomically transitions a continuation in StateExecuting
// back to StateExecuted so it becomes retryable. Used for operator-driven
// recovery of stuck executions. Returns a snapshot or (nil, false) if the
// continuation is missing or not in StateExecuting.
func (s *InMemoryStore) RecoverFromExecuting(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State != StateExecuting {
		return nil, false
	}
	c.State = StateExecuted
	return c.snapshot(), true
}

// ListExecutingIDs returns the IDs of all continuations currently in
// StateExecuting. Used by operator recovery flows to enumerate stuck work
// without exposing the full continuations payload.
func (s *InMemoryStore) ListExecutingIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.continuations))
	for id, c := range s.continuations {
		if c.State == StateExecuting {
			ids = append(ids, id)
		}
	}
	return ids
}

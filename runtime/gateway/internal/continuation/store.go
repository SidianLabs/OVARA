package continuation

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type State string

const (
	StateEscalated   State = "escalated"
	StateApproved    State = "approved"
	StateReady       State = "ready"
	StateDenied      State = "denied"
	StateResumed     State = "resumed"
	StateExpired     State = "expired"
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
	ResumedAt     *time.Time `json:"resumed_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ExpiredAt     *time.Time `json:"expired_at,omitempty"`
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
}

func (c *Continuation) CanResume() bool {
	return c.State == StateApproved || c.State == StateReady
}

func (c *Continuation) IsTerminal() bool {
	return c.State == StateDenied || c.State == StateExpired || c.State == StateResumed
}

func NewContinuation(decisionID, actionType, resource string) *Continuation {
	return &Continuation{
		ContinuationID: "cnt_" + uuid.New().String()[:16],
		DecisionID:     decisionID,
		ActionType:     actionType,
		Resource:       resource,
		State:          StateEscalated,
		CreatedAt:      time.Now().UTC(),
	}
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
	c.State = StateApproved
	c.ResolvedBy = resolvedBy
	now := time.Now().UTC()
	c.ApprovedAt = &now
}

func (c *Continuation) MarkReady() {
	if c.State == StateApproved {
		c.State = StateReady
	}
}

func (c *Continuation) MarkDenied(resolvedBy, reason string) {
	c.State = StateDenied
	c.ResolvedBy = resolvedBy
	c.DenyReason = reason
}

func (c *Continuation) MarkResumed() {
	c.State = StateResumed
	now := time.Now().UTC()
	c.ResumedAt = &now
}

func (c *Continuation) MarkExpired() {
	if !c.IsTerminal() {
		c.State = StateExpired
		now := time.Now().UTC()
		c.ExpiredAt = &now
	}
}

func (c *Continuation) IsReady() bool {
	return c.State == StateReady
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
	if c.State != StateApproved && c.State != StateReady {
		return false
	}
	if c.ExpiresAt != nil && time.Now().UTC().After(*c.ExpiresAt) {
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
	return c, ok
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
			result = append(result, c)
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
			result = append(result, c)
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
			result = append(result, c)
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
			result = append(result, c)
		}
	}
	return result
}

func (s *InMemoryStore) ListAll() []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		result = append(result, c)
	}
	return result
}
package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultPendingTTL is how long a pending approval can be approved. The
// proxy holds a request for its escalate window (60s by default) and
// then gives up; an approval given long after that lets nothing through
// and teaches the person to approve the agent's retry without reading it.
const DefaultPendingTTL = 10 * time.Minute

// ErrApprovalExpired is returned when approving a pending approval older
// than the TTL.
var ErrApprovalExpired = errors.New("approval expired: the agent is no longer waiting for it")

// DefaultMaxPendingPerAgent is how many approvals one agent may have
// waiting at once (see Open).
const DefaultMaxPendingPerAgent = 16

// ErrTooManyPending is returned by Open when the agent already has the
// maximum number of approvals waiting.
var ErrTooManyPending = errors.New("too many approvals waiting")

type Service struct {
	store Store

	mu                 sync.RWMutex
	pendingTTL         time.Duration // <= 0: pending approvals never expire
	maxPendingPerAgent int           // <= 0: no cap
	now                func() time.Time

	// openMu makes Open's count/dedupe check and the create one step.
	openMu sync.Mutex
}

func NewService(store Store) *Service {
	return &Service{store: store, pendingTTL: DefaultPendingTTL, maxPendingPerAgent: DefaultMaxPendingPerAgent, now: time.Now}
}

// SetPendingTTL sets how long a pending approval stays approvable; zero
// or less turns expiry off.
func (s *Service) SetPendingTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingTTL = d
}

func (s *Service) PendingTTL() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingTTL
}

// SetNow replaces the clock (tests).
func (s *Service) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *Service) clock() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now()
}

// expired reports whether a stored pending approval is past the TTL.
func (s *Service) expired(a *ApprovalRequest) bool {
	ttl := s.PendingTTL()
	return a.Status == StatusPending && ttl > 0 && s.clock().Sub(a.CreatedAt) > ttl
}

// view is what callers see: a stored pending approval past the TTL reads
// as expired. Store reads return copies, so this never touches the store.
func (s *Service) view(a *ApprovalRequest) *ApprovalRequest {
	if a != nil && s.expired(a) {
		a.Status = StatusExpired
	}
	return a
}

func (s *Service) viewAll(list []*ApprovalRequest) []*ApprovalRequest {
	for _, a := range list {
		s.view(a)
	}
	return list
}

func (s *Service) CreateApproval(req *CreateRequest) (*ApprovalRequest, error) {
	if req.DecisionID == "" {
		return nil, fmt.Errorf("decision_id is required")
	}
	if req.ActionType == "" {
		return nil, fmt.Errorf("action_type is required")
	}

	approvalID := fmt.Sprintf("apr_%s", uuid.New().String())
	approval := req.ToApproval(approvalID)
	approval.CreatedAt = s.clock().UTC()

	if err := s.store.Create(approval); err != nil {
		return nil, fmt.Errorf("creating approval: %w", err)
	}

	log.Printf("APPROVAL created approval_id=%s decision_id=%s action_type=%s agent_id=%s environment=%s",
		approvalID, req.DecisionID, req.ActionType, req.AgentID, req.Environment)

	return approval, nil
}

// Open is how an escalation asks a person: it creates an approval unless
// the same agent already has an identical one waiting (same action type,
// environment, resource and context), in which case that one is returned
// with reused=true, and it refuses with ErrTooManyPending once the agent
// has MaxPendingPerAgent approvals waiting. Expired approvals neither
// count nor get reused. Without these limits an agent can keep the queue
// full of cards and bury the one that matters.
func (s *Service) Open(req *CreateRequest) (a *ApprovalRequest, reused bool, err error) {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	key := dedupeKey(req.AgentID, string(req.ActionType), string(req.Environment), req.Resource, req.Context)
	waiting := 0
	for _, p := range s.ListPending() { // expired ones are already left out
		if p.AgentID != req.AgentID {
			continue
		}
		if dedupeKey(p.AgentID, string(p.ActionType), string(p.Environment), p.Resource, p.Context) == key {
			return p, true, nil
		}
		waiting++
	}
	if max := s.MaxPendingPerAgent(); max > 0 && waiting >= max {
		return nil, false, fmt.Errorf("%w: agent %q has %d approvals waiting", ErrTooManyPending, req.AgentID, waiting)
	}
	a, err = s.CreateApproval(req)
	return a, false, err
}

// dedupeKey identifies "the same request" for Open: a length-prefixed
// SHA-256 over the fields and the sorted context entries.
func dedupeKey(agent, action, env, resource string, ctx map[string]string) string {
	h := sha256.New()
	field := func(v string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	field(agent)
	field(action)
	field(env)
	field(resource)
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field(k)
		field(ctx[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SetMaxPendingPerAgent caps how many approvals one agent may have
// waiting at once; zero or less removes the cap.
func (s *Service) SetMaxPendingPerAgent(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxPendingPerAgent = n
}

func (s *Service) MaxPendingPerAgent() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxPendingPerAgent
}

func (s *Service) Approve(approvalID, resolvedBy string) (*ApprovalRequest, error) {
	// Atomic check+mutate under the store lock: a concurrent deny cannot
	// interleave between the pending check and the mutation, and an
	// approval cannot pass the expiry check and then expire before it is
	// written.
	notExpired := func(a *ApprovalRequest) error {
		if s.expired(a) {
			return fmt.Errorf("%w (%s, created %s)", ErrApprovalExpired, approvalID, a.CreatedAt.Format(time.RFC3339))
		}
		return nil
	}
	var approval *ApprovalRequest
	var err error
	if cr, ok := s.store.(ConditionalResolver); ok {
		approval, err = cr.ResolveIf(approvalID, StatusApproved, resolvedBy, "", notExpired)
	} else {
		cur, gerr := s.store.Get(approvalID)
		if gerr != nil {
			return nil, gerr
		}
		if err := notExpired(cur); err != nil {
			return nil, err
		}
		approval, err = s.store.Resolve(approvalID, StatusApproved, resolvedBy, "")
	}
	if err != nil {
		return nil, err
	}

	log.Printf("APPROVAL approved approval_id=%s resolved_by=%s action_type=%s decision_id=%s",
		approvalID, resolvedBy, approval.ActionType, approval.DecisionID)

	return approval, nil
}

func (s *Service) Deny(approvalID, resolvedBy, reason string) (*ApprovalRequest, error) {
	approval, err := s.store.Resolve(approvalID, StatusDenied, resolvedBy, reason)
	if err != nil {
		return nil, err
	}

	log.Printf("APPROVAL denied approval_id=%s resolved_by=%s reason=%q action_type=%s decision_id=%s",
		approvalID, resolvedBy, reason, approval.ActionType, approval.DecisionID)

	return approval, nil
}

func (s *Service) GetApproval(approvalID string) (*ApprovalRequest, error) {
	a, err := s.store.Get(approvalID)
	if err != nil {
		return nil, err
	}
	return s.view(a), nil
}

func (s *Service) ListAll() []*ApprovalRequest {
	return s.viewAll(s.store.ListAll())
}

// ListPending lists the approvals still waiting for a person, oldest
// first. Expired approvals are not listed.
func (s *Service) ListPending() []*ApprovalRequest {
	return s.ListByStatus(StatusPending)
}

// ListByStatus filters on the status callers see: "pending" leaves out
// expired approvals and "expired" lists them. Pending and expired lists
// are oldest first.
func (s *Service) ListByStatus(status Status) []*ApprovalRequest {
	stored := status
	if status == StatusExpired {
		stored = StatusPending
	}
	all := s.viewAll(s.store.ListByStatus(stored))
	if stored != StatusPending {
		return all
	}
	out := make([]*ApprovalRequest, 0, len(all))
	for _, a := range all {
		if a.Status == status {
			out = append(out, a)
		}
	}
	sortOldestFirst(out)
	return out
}

func (s *Service) ListByDecision(decisionID string) []*ApprovalRequest {
	return s.viewAll(s.store.ListByDecision(decisionID))
}

func sortOldestFirst(list []*ApprovalRequest) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		}
		return list[i].ApprovalID < list[j].ApprovalID
	})
}

// ResumeAction consumes the approval's single-use resume token atomically.
// A second resume for the same approval fails, preventing replay.
func (s *Service) ResumeAction(approvalID string) (*ResumeResult, error) {
	approval, err := s.store.ConsumeResume(approvalID)
	if err != nil {
		return nil, err
	}

	result := &ResumeResult{
		Approved:     true,
		ApprovalID:   approvalID,
		DecisionID:   approval.DecisionID,
		ActionType:   string(approval.ActionType),
		Resource:     approval.Resource,
		TrustScore:   approval.TrustScore,
		TrustLevel:   string(approval.TrustLevel),
		AnomalyCodes: approval.AnomalyCodes,
		ShieldActive: approval.ShieldActive,
		Restricted:   approval.Restricted,
	}

	log.Printf("APPROVAL resumed approval_id=%s decision_id=%s action_type=%s",
		approvalID, approval.DecisionID, approval.ActionType)

	return result, nil
}

type ResumeResult struct {
	Approved     bool     `json:"approved"`
	ApprovalID   string   `json:"approval_id"`
	DecisionID   string   `json:"decision_id"`
	ActionType   string   `json:"action_type"`
	Resource     string   `json:"resource"`
	TrustScore   float64  `json:"trust_score,omitempty"`
	TrustLevel   string   `json:"trust_level,omitempty"`
	AnomalyCodes []string `json:"anomaly_codes,omitempty"`
	ShieldActive bool     `json:"shield_active,omitempty"`
	Restricted   bool     `json:"restricted,omitempty"`
}

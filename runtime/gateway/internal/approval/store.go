package approval

import (
	"fmt"
	"sync"
)

type Store interface {
	Create(req *ApprovalRequest) error
	Get(id string) (*ApprovalRequest, error)
	Update(req *ApprovalRequest) error
	// Resolve atomically checks that the approval is pending and applies the
	// given decision (StatusApproved or StatusDenied) under one lock. This
	// closes the Get→IsPending→mutate→Update TOCTOU where a deny could win
	// against a concurrent approve (or vice versa) on a stale snapshot.
	Resolve(id string, decision Status, resolvedBy, reason string) (*ApprovalRequest, error)
	// ConsumeResume atomically verifies the approval is approved and its
	// single-use resume token is unconsumed, then marks it consumed. Makes
	// POST /v1/approval/{id}/resume single-use instead of replayable.
	ConsumeResume(id string) (*ApprovalRequest, error)
	ListAll() []*ApprovalRequest
	ListByStatus(status Status) []*ApprovalRequest
	ListByDecision(decisionID string) []*ApprovalRequest
}

// snapshot returns a copy of the approval so callers never share the live
// stored object (which the store may mutate under its lock).
func snapshotOf(a *ApprovalRequest) *ApprovalRequest {
	cp := *a
	return &cp
}

type InMemoryStore struct {
	mu    sync.RWMutex
	items map[string]*ApprovalRequest
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		items: make(map[string]*ApprovalRequest),
	}
}

func (s *InMemoryStore) Create(req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ApprovalID == "" {
		return fmt.Errorf("approval_id is required")
	}
	if _, exists := s.items[req.ApprovalID]; exists {
		return fmt.Errorf("approval already exists: %s", req.ApprovalID)
	}
	s.items[req.ApprovalID] = req
	return nil
}

func (s *InMemoryStore) Get(id string) (*ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("approval not found: %s", id)
	}
	return snapshotOf(req), nil
}

func (s *InMemoryStore) Update(req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[req.ApprovalID]; !exists {
		return fmt.Errorf("approval not found: %s", req.ApprovalID)
	}
	s.items[req.ApprovalID] = req
	return nil
}

func (s *InMemoryStore) Resolve(id string, decision Status, resolvedBy, reason string) (*ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("approval not found: %s", id)
	}
	if !req.IsPending() {
		return nil, fmt.Errorf("approval is not pending: %s", req.Status)
	}
	switch decision {
	case StatusApproved:
		req.Approve(resolvedBy)
	case StatusDenied:
		req.Deny(resolvedBy, reason)
	default:
		return nil, fmt.Errorf("invalid decision: %s", decision)
	}
	return snapshotOf(req), nil
}

func (s *InMemoryStore) ConsumeResume(id string) (*ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("approval not found: %s", id)
	}
	if !req.CanResume() {
		if req.Status != StatusApproved {
			return nil, fmt.Errorf("approval not approved: %s", req.Status)
		}
		return nil, fmt.Errorf("approval already resumed")
	}
	req.MarkResumed()
	return snapshotOf(req), nil
}

func (s *InMemoryStore) ListAll() []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ApprovalRequest, 0, len(s.items))
	for _, req := range s.items {
		result = append(result, snapshotOf(req))
	}
	return result
}

func (s *InMemoryStore) ListByStatus(status Status) []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalRequest
	for _, req := range s.items {
		if req.Status == status {
			result = append(result, snapshotOf(req))
		}
	}
	return result
}

func (s *InMemoryStore) ListByDecision(decisionID string) []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalRequest
	for _, req := range s.items {
		if req.DecisionID == decisionID {
			result = append(result, snapshotOf(req))
		}
	}
	return result
}

package store

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"ovara.services.approval/internal/models"
)

type Store interface {
	Create(a *models.Approval) error
	Get(id string) (*models.Approval, error)
	List(filter ListFilter) ([]*models.Approval, error)
	Resolve(id string, state models.ApprovalState, resolvedBy string, reason string) error
	ExpireOlderThan(before time.Time) (int, error)
	EvictExpired() int
	Count() int
}

type ListFilter struct {
	State     models.ApprovalState
	GatewayID string
	AgentID   string
	Limit     int
	Offset    int
}

type memoryStore struct {
	mu        sync.RWMutex
	approvals map[string]*models.Approval
	maxSize   int
}

func NewMemoryStore(maxSize int) Store {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &memoryStore{
		approvals: make(map[string]*models.Approval),
		maxSize:   maxSize,
	}
}

func (s *memoryStore) Create(a *models.Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.approvals) >= s.maxSize {
		return fmt.Errorf("store full: max %d approvals", s.maxSize)
	}
	if _, exists := s.approvals[a.ID]; exists {
		return fmt.Errorf("approval %s already exists", a.ID)
	}
	s.approvals[a.ID] = cloneApproval(a)
	return nil
}

// cloneApproval returns a deep copy of an approval so stored approvals and
// returned copies do not share the ResolvedAt pointer with callers.
func cloneApproval(a *models.Approval) *models.Approval {
	if a == nil {
		return nil
	}
	cp := *a
	if a.ResolvedAt != nil {
		t := *a.ResolvedAt
		cp.ResolvedAt = &t
	}
	return &cp
}

func (s *memoryStore) Get(id string) (*models.Approval, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.approvals[id]
	if !ok {
		return nil, fmt.Errorf("approval %s not found", id)
	}
	return cloneApproval(a), nil
}

func (s *memoryStore) List(filter ListFilter) ([]*models.Approval, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.Approval
	for _, a := range s.approvals {
		if filter.State != "" && a.State != filter.State {
			continue
		}
		if filter.GatewayID != "" && a.GatewayID != filter.GatewayID {
			continue
		}
		if filter.AgentID != "" && a.AgentID != filter.AgentID {
			continue
		}
		results = append(results, cloneApproval(a))
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	if filter.Offset >= len(results) {
		results = results[:0]
	} else if filter.Offset > 0 {
		results = results[filter.Offset:]
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	if filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	if results == nil {
		results = []*models.Approval{}
	}
	return results, nil
}

func (s *memoryStore) Resolve(id string, state models.ApprovalState, resolvedBy string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.approvals[id]
	if !ok {
		return fmt.Errorf("approval %s not found", id)
	}
	if a.State != models.StatePending {
		return fmt.Errorf("approval %s is already %s", id, a.State)
	}

	now := time.Now().UTC()
	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now) {
		a.State = models.StateExpired
		a.ResolvedAt = &now
		a.Reason = "auto-expired"
		return fmt.Errorf("approval %s has expired", id)
	}
	a.State = state
	a.ResolvedBy = resolvedBy
	a.Reason = reason
	a.ResolvedAt = &now
	return nil
}

func (s *memoryStore) ExpireOlderThan(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ExpireOlderThan expires pending approvals whose ExpiresAt deadline has
	// passed relative to "before" (callers pass time.Now().UTC()). Approvals
	// with a zero ExpiresAt never expire.
	count := 0
	for _, a := range s.approvals {
		if a.State == models.StatePending && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(before) {
			a.State = models.StateExpired
			now := time.Now().UTC()
			a.ResolvedAt = &now
			a.Reason = "auto-expired"
			count++
		}
	}
	return count, nil
}

// EvictExpired removes approvals already marked expired so they stop
// counting against maxSize.
func (s *memoryStore) EvictExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, a := range s.approvals {
		if a.State == models.StateExpired {
			delete(s.approvals, id)
			count++
		}
	}
	return count
}

func (s *memoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.approvals)
}

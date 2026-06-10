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
	s.approvals[a.ID] = a
	return nil
}

func (s *memoryStore) Get(id string) (*models.Approval, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.approvals[id]
	if !ok {
		return nil, fmt.Errorf("approval %s not found", id)
	}
	return a, nil
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
		results = append(results, a)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
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
	a.State = state
	a.ResolvedBy = resolvedBy
	a.Reason = reason
	a.ResolvedAt = &now
	return nil
}

func (s *memoryStore) ExpireOlderThan(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, a := range s.approvals {
		if a.State == models.StatePending && a.CreatedAt.Before(before) {
			a.State = models.StateExpired
			now := time.Now().UTC()
			a.ResolvedAt = &now
			a.Reason = "auto-expired"
			count++
			_ = id
		}
	}
	return count, nil
}

func (s *memoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.approvals)
}

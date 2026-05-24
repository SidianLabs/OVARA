package approval

import (
	"fmt"
	"sync"
)

type Store interface {
	Create(req *ApprovalRequest) error
	Get(id string) (*ApprovalRequest, error)
	Update(req *ApprovalRequest) error
	ListByStatus(status Status) []*ApprovalRequest
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
	return req, nil
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

func (s *InMemoryStore) ListByStatus(status Status) []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalRequest
	for _, req := range s.items {
		if req.Status == status {
			result = append(result, req)
		}
	}
	return result
}
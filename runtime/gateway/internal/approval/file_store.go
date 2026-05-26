package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type FileBackedStore struct {
	path  string
	mu    sync.RWMutex
	items map[string]*ApprovalRequest
}

func NewFileBackedStore(path string) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:  path,
		items: make(map[string]*ApprovalRequest),
	}
	if err := store.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load approvals from %s: %w", path, err)
		}
	}
	return store, nil
}

func (s *FileBackedStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var items []*ApprovalRequest
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("failed to parse approvals JSON: %w", err)
	}
	for _, req := range items {
		s.items[req.ApprovalID] = req
	}
	return nil
}

func (s *FileBackedStore) persist(items []*ApprovalRequest) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approvals: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write approvals file: %w", err)
	}
	return nil
}

func (s *FileBackedStore) Create(req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.ApprovalID == "" {
		return fmt.Errorf("approval_id is required")
	}
	if _, exists := s.items[req.ApprovalID]; exists {
		return fmt.Errorf("approval already exists: %s", req.ApprovalID)
	}
	s.items[req.ApprovalID] = req
	var all []*ApprovalRequest
	for _, r := range s.items {
		all = append(all, r)
	}
	return s.persist(all)
}

func (s *FileBackedStore) Get(id string) (*ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("approval not found: %s", id)
	}
	return req, nil
}

func (s *FileBackedStore) Update(req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[req.ApprovalID]; !exists {
		return fmt.Errorf("approval not found: %s", req.ApprovalID)
	}
	s.items[req.ApprovalID] = req
	var all []*ApprovalRequest
	for _, r := range s.items {
		all = append(all, r)
	}
	return s.persist(all)
}

func (s *FileBackedStore) ListByStatus(status Status) []*ApprovalRequest {
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

func (s *FileBackedStore) ListByDecision(decisionID string) []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ApprovalRequest
	for _, req := range s.items {
		if req.DecisionID == decisionID {
			result = append(result, req)
		}
	}
	return result
}

func (s *FileBackedStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[id]; !exists {
		return fmt.Errorf("approval not found: %s", id)
	}
	delete(s.items, id)
	var all []*ApprovalRequest
	for _, r := range s.items {
		all = append(all, r)
	}
	return s.persist(all)
}

func (s *FileBackedStore) Stats() (pending, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.items)
	for _, req := range s.items {
		if req.Status == StatusPending {
			pending++
		}
	}
	return pending, total
}
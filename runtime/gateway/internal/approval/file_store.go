package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"ovara.runtime.gateway/internal/persist"
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

// persist writes the whole store via tmp-file + fsync + rename so a crash
// mid-write cannot leave a truncated/corrupt approvals file. Callers must
// hold s.mu.
func (s *FileBackedStore) persist(items []*ApprovalRequest) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approvals: %w", err)
	}
	if err := persist.WriteFileAtomic(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write approvals file: %w", err)
	}
	return nil
}

// persistAll snapshots the map and persists it. Callers must hold s.mu.
func (s *FileBackedStore) persistAll() error {
	var all []*ApprovalRequest
	for _, r := range s.items {
		all = append(all, r)
	}
	return s.persist(all)
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
	return s.persistAll()
}

func (s *FileBackedStore) Get(id string) (*ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("approval not found: %s", id)
	}
	return snapshotOf(req), nil
}

func (s *FileBackedStore) Update(req *ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[req.ApprovalID]; !exists {
		return fmt.Errorf("approval not found: %s", req.ApprovalID)
	}
	s.items[req.ApprovalID] = req
	return s.persistAll()
}

func (s *FileBackedStore) Resolve(id string, decision Status, resolvedBy, reason string) (*ApprovalRequest, error) {
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
	if err := s.persistAll(); err != nil {
		return nil, err
	}
	return snapshotOf(req), nil
}

func (s *FileBackedStore) ConsumeResume(id string) (*ApprovalRequest, error) {
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
	if err := s.persistAll(); err != nil {
		return nil, err
	}
	return snapshotOf(req), nil
}

func (s *FileBackedStore) ListAll() []*ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ApprovalRequest, 0, len(s.items))
	for _, req := range s.items {
		result = append(result, snapshotOf(req))
	}
	return result
}

func (s *FileBackedStore) ListByStatus(status Status) []*ApprovalRequest {
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

func (s *FileBackedStore) ListByDecision(decisionID string) []*ApprovalRequest {
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

func (s *FileBackedStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[id]; !exists {
		return fmt.Errorf("approval not found: %s", id)
	}
	delete(s.items, id)
	return s.persistAll()
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

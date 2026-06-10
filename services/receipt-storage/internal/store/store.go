package store

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"ovara.services.receipt/internal/models"
)

type Store interface {
	Archive(r *models.Receipt) error
	Get(id string) (*models.Receipt, error)
	List(filter ListFilter) ([]*models.Receipt, error)
	Verify(id string) (*models.VerificationResult, error)
	Count() int
	CountByOrg(orgID string) int
}

type ListFilter struct {
	OrganizationID string
	GatewayID      string
	Decision       string
	ActionType     string
	StartDate      time.Time
	EndDate        time.Time
	Limit          int
	Offset         int
}

type memoryStore struct {
	mu       sync.RWMutex
	receipts map[string]*models.Receipt
	maxSize  int
}

func NewMemoryStore(maxSize int) Store {
	if maxSize <= 0 {
		maxSize = 100000
	}
	return &memoryStore{
		receipts: make(map[string]*models.Receipt),
		maxSize:  maxSize,
	}
}

func (s *memoryStore) Archive(r *models.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.receipts) >= s.maxSize {
		return fmt.Errorf("store full: max %d receipts", s.maxSize)
	}
	if _, exists := s.receipts[r.ID]; exists {
		return fmt.Errorf("receipt %s already archived", r.ID)
	}
	s.receipts[r.ID] = r
	return nil
}

func (s *memoryStore) Get(id string) (*models.Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.receipts[id]
	if !ok {
		return nil, fmt.Errorf("receipt %s not found", id)
	}
	return r, nil
}

func (s *memoryStore) List(filter ListFilter) ([]*models.Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.Receipt
	for _, r := range s.receipts {
		if filter.OrganizationID != "" && r.OrganizationID != filter.OrganizationID {
			continue
		}
		if filter.GatewayID != "" && r.GatewayID != filter.GatewayID {
			continue
		}
		if filter.Decision != "" && r.Decision != filter.Decision {
			continue
		}
		if filter.ActionType != "" && r.ActionType != filter.ActionType {
			continue
		}
		if !filter.StartDate.IsZero() && r.IssuedAt.Before(filter.StartDate) {
			continue
		}
		if !filter.EndDate.IsZero() && r.IssuedAt.After(filter.EndDate) {
			continue
		}
		results = append(results, r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].IssuedAt.After(results[j].IssuedAt)
	})

	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	if results == nil {
		results = []*models.Receipt{}
	}
	return results, nil
}

func (s *memoryStore) Verify(id string) (*models.VerificationResult, error) {
	r, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	digest := r.Digest()
	valid := len(r.Signature) >= 64 && r.Signature != ""

	var errs []string
	if !valid {
		errs = append(errs, "signature is too short or empty")
	}

	return &models.VerificationResult{
		Valid:         valid,
		ReceiptDigest: digest,
		Errors:        errs,
	}, nil
}

func (s *memoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receipts)
}

func (s *memoryStore) CountByOrg(orgID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, r := range s.receipts {
		if r.OrganizationID == orgID {
			count++
		}
	}
	return count
}

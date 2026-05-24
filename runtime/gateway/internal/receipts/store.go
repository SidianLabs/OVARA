package receipts

import (
	"fmt"
	"sync"

	"ovara.runtime.gateway/internal/models"
)

type Store interface {
	Put(receipt *models.Receipt) error
	Get(id string) (*models.Receipt, error)
	ListByDecision(decisionID string) []*models.Receipt
	ListByAgent(agentID string) []*models.Receipt
	ListAll() []*models.Receipt
}

type InMemoryStore struct {
	mu      sync.RWMutex
	receipts map[string]*models.Receipt
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		receipts: make(map[string]*models.Receipt),
	}
}

func (s *InMemoryStore) Put(receipt *models.Receipt) error {
	if receipt.ReceiptID == "" {
		return fmt.Errorf("receipt_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts[receipt.ReceiptID] = receipt
	return nil
}

func (s *InMemoryStore) Get(id string) (*models.Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, ok := s.receipts[id]
	if !ok {
		return nil, fmt.Errorf("receipt not found: %s", id)
	}
	return receipt, nil
}

func (s *InMemoryStore) ListByDecision(decisionID string) []*models.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.Receipt
	for _, r := range s.receipts {
		if r.DecisionID == decisionID {
			result = append(result, r)
		}
	}
	return result
}

func (s *InMemoryStore) ListByAgent(agentID string) []*models.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.Receipt
	for _, r := range s.receipts {
		if r.AgentID == agentID {
			result = append(result, r)
		}
	}
	return result
}

func (s *InMemoryStore) ListAll() []*models.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.Receipt
	for _, r := range s.receipts {
		result = append(result, r)
	}
	return result
}
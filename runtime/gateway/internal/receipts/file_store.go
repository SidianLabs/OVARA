package receipts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type FileBackedStore struct {
	path     string
	mu       sync.RWMutex
	receipts map[string]*models.Receipt
	// Bounded retention
	maxSize    int
	maxAge     time.Duration
	lastSentAt time.Time
}

func NewFileBackedStore(path string, maxSize int, maxAge time.Duration) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:     path,
		receipts: make(map[string]*models.Receipt),
		maxSize:  maxSize,
		maxAge:   maxAge,
	}
	if err := store.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load receipts from %s: %w", path, err)
		}
	}
	return store, nil
}

func (s *FileBackedStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var receipts []*models.Receipt
	if err := json.Unmarshal(data, &receipts); err != nil {
		return fmt.Errorf("failed to parse receipts JSON: %w", err)
	}
	for _, r := range receipts {
		s.receipts[r.ReceiptID] = r
	}
	return nil
}

func (s *FileBackedStore) persist() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	s.mu.RLock()
	var receipts []*models.Receipt
	for _, r := range s.receipts {
		receipts = append(receipts, r)
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(receipts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal receipts: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write receipts file: %w", err)
	}
	return nil
}

func (s *FileBackedStore) Put(receipt *models.Receipt) error {
	if receipt.ReceiptID == "" {
		return fmt.Errorf("receipt_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts[receipt.ReceiptID] = receipt
	if s.maxSize > 0 && len(s.receipts) > s.maxSize {
		s.evictOldest(len(s.receipts) - s.maxSize)
	}
	go s.persist()
	return nil
}

func (s *FileBackedStore) evictOldest(count int) {
	var oldest []*models.Receipt
	for _, r := range s.receipts {
		oldest = append(oldest, r)
	}
	for i := 0; i < len(oldest)-1; i++ {
		for j := i + 1; j < len(oldest); j++ {
			if oldest[i].IssuedAt.After(oldest[j].IssuedAt) {
				oldest[i], oldest[j] = oldest[j], oldest[i]
			}
		}
	}
	for i := 0; i < count && i < len(oldest); i++ {
		delete(s.receipts, oldest[i].ReceiptID)
	}
}

func (s *FileBackedStore) Get(id string) (*models.Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, ok := s.receipts[id]
	if !ok {
		return nil, fmt.Errorf("receipt not found: %s", id)
	}
	return receipt, nil
}

func (s *FileBackedStore) ListByDecision(decisionID string) []*models.Receipt {
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

func (s *FileBackedStore) ListByAgent(agentID string) []*models.Receipt {
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

func (s *FileBackedStore) ListAll() []*models.Receipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*models.Receipt
	for _, r := range s.receipts {
		result = append(result, r)
	}
	return result
}

func (s *FileBackedStore) Stats() (count, max int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receipts), s.maxSize
}
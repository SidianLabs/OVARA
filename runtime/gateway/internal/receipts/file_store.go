package receipts

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/persist"
	"ovara.runtime.gateway/internal/record"
)

type FileBackedStore struct {
	path     string
	journal  *record.Journal // non-nil → signed journal mode (P2.4)
	tipsSink func(seq uint64, hash string) error
	mu       sync.RWMutex
	receipts map[string]*models.Receipt
	maxSize  int
	maxAge   time.Duration
	evictedIDs []string // ids evicted this Put — journaled as compact
}

// NewFileBackedStore opens the receipts store. A non-nil record.Binding
// switches it into signed-journal mode (P2.4): the store becomes the
// durable decision journal (D9) — one signed envelope per receipt,
// hash-chained and domain-bound. Unsigned legacy files fail closed;
// run `gwctl migrate` first.
func NewFileBackedStore(path string, maxSize int, maxAge time.Duration, bindings ...*record.Binding) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:     path,
		receipts: make(map[string]*models.Receipt),
		maxSize:  maxSize,
		maxAge:   maxAge,
	}
	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		j, err := record.Open("receipts", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor, store.foldEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to fold receipts journal: %w", err)
		}
		store.journal = j
		return store, nil
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

// persist writes the whole store via tmp-file + fsync + rename so a crash
// mid-write cannot leave a truncated/corrupt receipts file.
func (s *FileBackedStore) persist(receipts []*models.Receipt) error {
	data, err := json.MarshalIndent(receipts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal receipts: %w", err)
	}
	if err := persist.WriteFileAtomic(s.path, data, 0644); err != nil {
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
	if s.journal != nil {
		if err := s.persistJournalLocked(receipt); err != nil {
			return err
		}
		if len(s.evictedIDs) > 0 {
			data, _ := json.Marshal(map[string]any{"removed_ids": s.evictedIDs})
			seq, tip, err := s.journal.Append(record.TypeCompact, "", json.RawMessage(data), nil)
			s.evictedIDs = nil
			if err != nil {
				return err
			}
			if s.tipsSink != nil {
				return s.tipsSink(seq, tip)
			}
		}
		return nil
	}
	var all []*models.Receipt
	for _, r := range s.receipts {
		all = append(all, r)
	}
	return s.persist(all)
}

// persistJournalLocked appends the receipt as a signed journal record
// and commits the new tip to the ledger sink. Callers must hold s.mu.
func (s *FileBackedStore) persistJournalLocked(r *models.Receipt) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}
	seq, tip, err := s.journal.Append("receipt", r.ReceiptID, json.RawMessage(data), nil)
	if err != nil {
		return err
	}
	if s.tipsSink != nil {
		return s.tipsSink(seq, tip)
	}
	return nil
}

// SetTipsSink wires the committed-floor hook (gwidentity tip-ledger).
// Must be called before concurrent use.
func (s *FileBackedStore) SetTipsSink(fn func(seq uint64, hash string) error) {
	s.tipsSink = fn
}

// JournalTip exposes the journal's committed (seq, tip hash).
// Zero values in legacy mode.
func (s *FileBackedStore) JournalTip() (uint64, string) {
	if s.journal == nil {
		return 0, ""
	}
	return s.journal.Tip()
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
		s.evictedIDs = append(s.evictedIDs, oldest[i].ReceiptID)
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
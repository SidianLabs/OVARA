package approval

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"ovara.runtime.gateway/internal/persist"
	"ovara.runtime.gateway/internal/record"
)

type FileBackedStore struct {
	path       string
	journal    *record.Journal // non-nil → signed journal mode (P2.4)
	tipsSink   func(seq uint64, hash string) error
	mu         sync.RWMutex
	items      map[string]*ApprovalRequest
	tombstones map[string]bool
	// envs holds the latest journal envelope per record id — the signed
	// provenance artifact a lineage emitter hands to a verifier so the
	// approval's approver-root signature travels with it.
	envs map[string]*record.Envelope
}

// NewFileBackedStore opens the approval store. A non-nil record.Binding
// switches the file into signed-journal mode (P2.4): records are signed
// envelopes folded through the total transition table at open. The
// legacy whole-file format is not a journal — run `gwctl migrate` to
// convert it; a nil binding preserves legacy behaviour exactly.
func NewFileBackedStore(path string, bindings ...*record.Binding) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:       path,
		items:      make(map[string]*ApprovalRequest),
		tombstones: map[string]bool{},
		envs:       map[string]*record.Envelope{},
	}
	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		j, err := record.Open("approval", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor,
			func(env *record.Envelope) error {
				if env.Type == "approval" {
					cp := *env
					store.envs[env.RecordID] = &cp
				}
				return store.foldEvent(env)
			})
		if err != nil {
			return nil, fmt.Errorf("failed to fold approval journal: %w", err)
		}
		store.journal = j
		return store, nil
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

// appendLocked appends one signed record to the journal and commits the
// new tip to the ledger sink. Callers must hold s.mu; journal mode only.
func (s *FileBackedStore) appendLocked(req *ApprovalRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %w", err)
	}
	seq, tip, err := s.journal.Append("approval", req.ApprovalID, json.RawMessage(data), nil)
	if err != nil {
		return err
	}
	s.envs[req.ApprovalID] = s.journal.LastEnvelope()
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

// EnvelopeFor returns the latest approver-signed journal envelope for
// an approval id — nil in unsigned/legacy mode or when unknown. The
// envelope's key_ref + signature are the offline provenance proof that
// this record was minted under the approver root (C2-B A1).
func (s *FileBackedStore) EnvelopeFor(id string) *record.Envelope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.envs[id]
}

// JournalTip exposes the journal's committed (seq, tip hash) for
// open-time floor ratcheting. Zero values in legacy mode.
func (s *FileBackedStore) JournalTip() (uint64, string) {
	if s.journal == nil {
		return 0, ""
	}
	return s.journal.Tip()
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
	if s.journal != nil {
		if s.tombstones[req.ApprovalID] {
			return fmt.Errorf("approval id is tombstoned: %s", req.ApprovalID)
		}
		if err := s.appendLocked(req); err != nil {
			return err
		}
	}
	s.items[req.ApprovalID] = req
	if s.journal != nil {
		return nil
	}
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
	if s.journal != nil {
		if err := s.appendLocked(req); err != nil {
			return err
		}
	}
	s.items[req.ApprovalID] = req
	if s.journal != nil {
		return nil
	}
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
	if s.journal != nil {
		if err := s.appendLocked(req); err != nil {
			return nil, err
		}
		return snapshotOf(req), nil
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
	if s.journal != nil {
		if err := s.appendLocked(req); err != nil {
			log.Printf("approval store: failed to persist resume of %s: %v", id, err)
		}
		return snapshotOf(req), nil
	}
	if err := s.persistAll(); err != nil {
		// The in-memory resume was already applied; returning the error here
		// would tell the caller the consume failed and invite a retry that
		// then sees "already resumed". Match the continuation store's
		// persistLocked approach: log the write failure and still report
		// success so in-memory and reported state stay consistent.
		log.Printf("approval store: failed to persist resume of %s: %v", id, err)
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
	if s.journal != nil {
		// Tombstone, not deletion — the id stays dead in history.
		data, _ := json.Marshal(map[string]any{"state": string(s.items[id].Status)})
		seq, tip, err := s.journal.Append(record.TypeTombstone, id, json.RawMessage(data), nil)
		if err != nil {
			return err
		}
		if s.tipsSink != nil {
			if err := s.tipsSink(seq, tip); err != nil {
				return err
			}
		}
		s.tombstones[id] = true
	}
	delete(s.items, id)
	if s.journal != nil {
		return nil
	}
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

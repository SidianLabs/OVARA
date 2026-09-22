package capabilities

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/persist"
	"ovara.runtime.gateway/internal/record"
)

// touchPersistInterval debounces Touch persistence: LastSeenAt is updated in
// memory on every use but written to disk at most once per interval, so a
// busy lease does not trigger a quadratic whole-file rewrite per call.
const touchPersistInterval = 5 * time.Second

type FileBackedStore struct {
	path     string
	signer   *record.Signer      // non-nil → sealed-file mode (P2.4)
	fileSeq  uint64
	fileHash string
	tipsSink func(seq uint64, hash string) error
	mu       sync.RWMutex
	fileMu   sync.Mutex
	leases   map[string]*TrackedLease
	maxSize  int
	maxAge   time.Duration
	lastPersist time.Time
}

// NewFileBackedStore opens the tracked-lease store. A non-nil
// record.Binding switches it into sealed-file mode (P2.4): snapshots
// are signed whole-file envelopes with a file_seq chain — silent
// replacement or rollback fails closed.
func NewFileBackedStore(path string, maxSize int, maxAge time.Duration, bindings ...*record.Binding) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:    path,
		leases:  make(map[string]*TrackedLease),
		maxSize: maxSize,
		maxAge:  maxAge,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for capabilities store: %w", err)
	}
	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		store.signer = binding.Signer
		payload, seq, hash, err := record.OpenSealedFile("capabilities", path, binding.Signer.Domain(), binding.Resolve, binding.Floor)
		if err != nil {
			return nil, err
		}
		if payload == nil {
			return store, nil
		}
		var leases []*TrackedLease
		if err := json.Unmarshal(payload, &leases); err != nil {
			return nil, fmt.Errorf("failed to parse capabilities JSON: %w", err)
		}
		store.fileSeq, store.fileHash = seq, hash
		for _, l := range leases {
			store.leases[l.Lease.LeaseID] = l
		}
		return store, nil
	}
	if err := store.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load capabilities from %s: %w", path, err)
		}
	}
	return store, nil
}

func (s *FileBackedStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var leases []*TrackedLease
	if err := json.Unmarshal(data, &leases); err != nil {
		return fmt.Errorf("failed to parse capabilities JSON: %w", err)
	}
	for _, l := range leases {
		s.leases[l.Lease.LeaseID] = l
	}
	return nil
}

// persist writes the whole store via tmp-file + fsync + rename so a crash
// mid-write cannot leave a truncated/corrupt capabilities file.
func (s *FileBackedStore) persist(snapshot []*TrackedLease) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if s.signer != nil {
		prevBytes, err := os.ReadFile(s.path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read capabilities file: %w", err)
		}
		sealed, err := record.SealFile("capabilities", s.signer, data, prevBytes, s.fileSeq)
		if err != nil {
			return fmt.Errorf("failed to seal capabilities file: %w", err)
		}
		if err := persist.WriteFileAtomic(s.path, sealed, 0644); err != nil {
			return fmt.Errorf("failed to write capabilities file: %w", err)
		}
		s.fileSeq++
		s.fileHash = record.TipHash(sealed)
		if s.tipsSink != nil {
			if err := s.tipsSink(s.fileSeq, s.fileHash); err != nil {
				return fmt.Errorf("tip-ledger commit failed (sealed write is durable, floor not advanced): %w", err)
			}
		}
		return nil
	}
	if err := persist.WriteFileAtomic(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write capabilities file: %w", err)
	}
	return nil
}

// SetTipsSink wires the committed-floor hook (gwidentity tip-ledger).
// Must be called before concurrent use.
func (s *FileBackedStore) SetTipsSink(fn func(seq uint64, hash string) error) {
	s.tipsSink = fn
}

// JournalTip exposes the sealed file's committed (file_seq, hash).
// Zero values in legacy mode.
func (s *FileBackedStore) JournalTip() (uint64, string) {
	return s.fileSeq, s.fileHash
}

func (s *FileBackedStore) snapshot() []*TrackedLease {
	var all []*TrackedLease
	for _, l := range s.leases {
		all = append(all, l.Clone())
	}
	return all
}

func (s *FileBackedStore) Track(lease *models.CapabilityLease, gatewayID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.leases[lease.LeaseID]
	if ok {
		return existing.Lease.LeaseID
	}

	tracked := &TrackedLease{
		Lease:     lease,
		CreatedAt: time.Now().UTC(),
		GatewayID: gatewayID,
	}
	s.leases[lease.LeaseID] = tracked

	if s.maxSize > 0 && len(s.leases) > s.maxSize {
		s.evictOldest(len(s.leases) - s.maxSize)
	}

	s.persist(s.snapshot())
	return lease.LeaseID
}

func (s *FileBackedStore) evictOldest(count int) {
	var oldest []*TrackedLease
	for _, l := range s.leases {
		oldest = append(oldest, l)
	}
	for i := 0; i < len(oldest)-1; i++ {
		for j := i + 1; j < len(oldest); j++ {
			if oldest[i].CreatedAt.After(oldest[j].CreatedAt) {
				oldest[i], oldest[j] = oldest[j], oldest[i]
			}
		}
	}
	for i := 0; i < count && i < len(oldest); i++ {
		delete(s.leases, oldest[i].Lease.LeaseID)
	}
}

func (s *FileBackedStore) Get(leaseID string) (*TrackedLease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tracked, ok := s.leases[leaseID]
	return tracked, ok
}

func (s *FileBackedStore) List() []*TrackedLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*TrackedLease, 0, len(s.leases))
	for _, tracked := range s.leases {
		result = append(result, tracked)
	}
	return result
}

func (s *FileBackedStore) ListActive() []*TrackedLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*TrackedLease, 0)
	now := time.Now()
	for _, tracked := range s.leases {
		if tracked.RevokedAt == nil && tracked.Lease.Expiry.After(now) {
			result = append(result, tracked)
		}
	}
	return result
}

func (s *FileBackedStore) ListRevoked() []*TrackedLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*TrackedLease, 0)
	for _, tracked := range s.leases {
		if tracked.RevokedAt != nil {
			result = append(result, tracked)
		}
	}
	return result
}

func (s *FileBackedStore) Revoke(leaseID, reason string) (*TrackedLease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tracked, ok := s.leases[leaseID]
	if !ok {
		return nil, false
	}
	if tracked.RevokedAt != nil {
		return tracked, true
	}
	now := time.Now().UTC()
	tracked.RevokedAt = &now
	tracked.RevocationReason = reason
	s.persist(s.snapshot())
	return tracked, true
}

func (s *FileBackedStore) IsRevoked(leaseID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tracked, ok := s.leases[leaseID]
	if !ok {
		return false
	}
	return tracked.RevokedAt != nil
}

func (s *FileBackedStore) Touch(leaseID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tracked, ok := s.leases[leaseID]
	if !ok {
		return
	}
	now := time.Now().UTC()
	tracked.LastSeenAt = &now
	// Debounced: persist at most once per touchPersistInterval regardless of
	// call rate. LastSeenAt is a liveness hint, not an audit record, so a
	// few seconds of staleness on crash is acceptable.
	if s.lastPersist.IsZero() || now.Sub(s.lastPersist) >= touchPersistInterval {
		s.lastPersist = now
		s.persist(s.snapshot())
	}
}

func (s *FileBackedStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = make(map[string]*TrackedLease)
	s.persist(s.snapshot())
}

func (s *FileBackedStore) Stats() (total, active, revoked int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.leases)
	now := time.Now()
	for _, tracked := range s.leases {
		if tracked.RevokedAt != nil {
			revoked++
		} else if tracked.Lease.Expiry.After(now) {
			active++
		}
	}
	return
}

func (s *FileBackedStore) FilePath() string {
	return s.path
}

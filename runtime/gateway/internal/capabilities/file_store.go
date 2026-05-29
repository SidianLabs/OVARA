package capabilities

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
	fileMu   sync.Mutex
	leases   map[string]*TrackedLease
	maxSize  int
	maxAge   time.Duration
}

func NewFileBackedStore(path string, maxSize int, maxAge time.Duration) (*FileBackedStore, error) {
	store := &FileBackedStore{
		path:    path,
		leases:  make(map[string]*TrackedLease),
		maxSize: maxSize,
		maxAge:  maxAge,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for capabilities store: %w", err)
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

func (s *FileBackedStore) persist(snapshot []*TrackedLease) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write capabilities file: %w", err)
	}
	return nil
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
	s.persist(s.snapshot())
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

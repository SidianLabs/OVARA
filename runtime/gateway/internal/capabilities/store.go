package capabilities

import (
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type TrackedLease struct {
	Lease            *models.CapabilityLease
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevocationReason string
	GatewayID        string
	LastSeenAt       *time.Time
}

func (t *TrackedLease) Clone() *TrackedLease {
	cloned := &TrackedLease{
		CreatedAt:        t.CreatedAt,
		RevocationReason: t.RevocationReason,
		GatewayID:        t.GatewayID,
	}
	if t.Lease != nil {
		clonedLease := *t.Lease
		if len(t.Lease.AllowedActions) > 0 {
			clonedLease.AllowedActions = make([]string, len(t.Lease.AllowedActions))
			copy(clonedLease.AllowedActions, t.Lease.AllowedActions)
		}
		cloned.Lease = &clonedLease
	}
	if t.RevokedAt != nil {
		revoked := *t.RevokedAt
		cloned.RevokedAt = &revoked
	}
	if t.LastSeenAt != nil {
		lastSeen := *t.LastSeenAt
		cloned.LastSeenAt = &lastSeen
	}
	return cloned
}

type LeaseHistoryEntry struct {
	LeaseID    string    `json:"lease_id"`
	Event      string    `json:"event"`
	Timestamp  time.Time `json:"timestamp"`
	GatewayID  string    `json:"gateway_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Action     string    `json:"action,omitempty"`
	Resource   string    `json:"resource,omitempty"`
}

type Store interface {
	Track(lease *models.CapabilityLease, gatewayID string) string
	Get(leaseID string) (*TrackedLease, bool)
	List() []*TrackedLease
	ListActive() []*TrackedLease
	ListRevoked() []*TrackedLease
	Revoke(leaseID, reason string) (*TrackedLease, bool)
	IsRevoked(leaseID string) bool
	Touch(leaseID string)
}

type InMemoryStore struct {
	mu     sync.RWMutex
	leases map[string]*TrackedLease
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		leases: make(map[string]*TrackedLease),
	}
}

func (s *InMemoryStore) Track(lease *models.CapabilityLease, gatewayID string) string {
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
	return lease.LeaseID
}

func (s *InMemoryStore) Get(leaseID string) (*TrackedLease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tracked, ok := s.leases[leaseID]
	return tracked, ok
}

func (s *InMemoryStore) List() []*TrackedLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*TrackedLease, 0, len(s.leases))
	for _, tracked := range s.leases {
		result = append(result, tracked)
	}
	return result
}

func (s *InMemoryStore) ListActive() []*TrackedLease {
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

func (s *InMemoryStore) ListRevoked() []*TrackedLease {
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

func (s *InMemoryStore) Revoke(leaseID, reason string) (*TrackedLease, bool) {
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
	return tracked, true
}

func (s *InMemoryStore) IsRevoked(leaseID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tracked, ok := s.leases[leaseID]
	if !ok {
		return false
	}
	return tracked.RevokedAt != nil
}

func (s *InMemoryStore) Touch(leaseID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tracked, ok := s.leases[leaseID]
	if !ok {
		return
	}
	now := time.Now().UTC()
	tracked.LastSeenAt = &now
}

func (s *InMemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = make(map[string]*TrackedLease)
}

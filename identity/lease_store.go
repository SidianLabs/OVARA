package identity

import (
	"fmt"
	"sync"
)

type LeaseStore struct {
	mu     sync.RWMutex
	leases map[string]*CapabilityLease
}

func NewLeaseStore() *LeaseStore {
	return &LeaseStore{
		leases: make(map[string]*CapabilityLease),
	}
}

func (s *LeaseStore) Store(lease *CapabilityLease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.leases[lease.LeaseID]; exists {
		return fmt.Errorf("lease already exists: %s", lease.LeaseID)
	}
	s.leases[lease.LeaseID] = lease
	return nil
}

func (s *LeaseStore) Get(leaseID string) (*CapabilityLease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lease, ok := s.leases[leaseID]
	return lease, ok
}

func (s *LeaseStore) List() []*CapabilityLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*CapabilityLease, 0, len(s.leases))
	for _, l := range s.leases {
		result = append(result, l)
	}
	return result
}

func (s *LeaseStore) ListBySubject(subject string) []*CapabilityLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*CapabilityLease
	for _, l := range s.leases {
		if l.Subject == subject {
			result = append(result, l)
		}
	}
	return result
}

func (s *LeaseStore) ListByIssuer(issuerID string) []*CapabilityLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*CapabilityLease
	for _, l := range s.leases {
		if l.Issuer == issuerID {
			result = append(result, l)
		}
	}
	return result
}

func (s *LeaseStore) ListActive() []*CapabilityLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*CapabilityLease
	for _, l := range s.leases {
		if !l.IsExpired() {
			result = append(result, l)
		}
	}
	return result
}

func (s *LeaseStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.leases)
}

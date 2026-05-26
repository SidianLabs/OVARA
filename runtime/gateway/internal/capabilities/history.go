package capabilities

import (
	"sync"
	"time"
)

const MaxHistoryEntries = 10000

type HistoryStore struct {
	mu      sync.RWMutex
	entries []LeaseHistoryEntry
}

func NewHistoryStore() *HistoryStore {
	return &HistoryStore{
		entries: make([]LeaseHistoryEntry, 0, MaxHistoryEntries),
	}
}

func (s *HistoryStore) Append(entry LeaseHistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	if len(s.entries) > MaxHistoryEntries {
		s.entries = s.entries[len(s.entries)-MaxHistoryEntries:]
	}
}

func (s *HistoryStore) ListByLeaseID(leaseID string) []LeaseHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []LeaseHistoryEntry
	for _, e := range s.entries {
		if e.LeaseID == leaseID {
			result = append(result, e)
		}
	}
	return result
}

func (s *HistoryStore) ListRecent(limit int) []LeaseHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	if limit > len(s.entries) {
		limit = len(s.entries)
	}
	result := make([]LeaseHistoryEntry, limit)
	copy(result, s.entries[len(s.entries)-limit:])
	return result
}

func (s *HistoryStore) ListBySubject(subject string) []LeaseHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []LeaseHistoryEntry
	for _, e := range s.entries {
		if e.Subject == subject {
			result = append(result, e)
		}
	}
	return result
}

func (s *HistoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *HistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([]LeaseHistoryEntry, 0, MaxHistoryEntries)
}

func LeaseTrackedEntry(leaseID, gatewayID, subject, issuer string) LeaseHistoryEntry {
	return LeaseHistoryEntry{
		LeaseID:   leaseID,
		Event:     "tracked",
		Timestamp: time.Now().UTC(),
		GatewayID: gatewayID,
		Subject:   subject,
		Issuer:    issuer,
	}
}

func LeaseUsedEntry(leaseID, gatewayID string) LeaseHistoryEntry {
	return LeaseHistoryEntry{
		LeaseID:   leaseID,
		Event:     "used",
		Timestamp: time.Now().UTC(),
		GatewayID: gatewayID,
	}
}

func LeaseRevokedEntry(leaseID, gatewayID, reason, subject, issuer string) LeaseHistoryEntry {
	return LeaseHistoryEntry{
		LeaseID:   leaseID,
		Event:     "revoked",
		Timestamp: time.Now().UTC(),
		GatewayID: gatewayID,
		Reason:    reason,
		Subject:   subject,
		Issuer:    issuer,
	}
}

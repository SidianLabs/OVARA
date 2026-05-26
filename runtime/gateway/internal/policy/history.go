package policy

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

type PolicyHistoryEntry struct {
	ID              string    `json:"id"`
	Version         string    `json:"version"`
	Rules           []Rule    `json:"rules"`
	RuleCount       int       `json:"rule_count"`
	Source          string    `json:"source"`
	PreviousVersion string    `json:"previous_version,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	GatewayID       string    `json:"gateway_id,omitempty"`
}

const (
	PolicySourcePromote  = "promote"
	PolicySourceRollback = "rollback"
	PolicySourceRestore  = "restore"
	PolicySourceReload   = "reload"
)

type PolicyHistoryStore interface {
	Add(entry *PolicyHistoryEntry) string
	Get(id string) (*PolicyHistoryEntry, bool)
	List() []*PolicyHistoryEntry
	Latest() (*PolicyHistoryEntry, bool)
	Clear()
}

type InMemoryPolicyHistory struct {
	mu      sync.RWMutex
	entries map[string]*PolicyHistoryEntry
}

func NewInMemoryPolicyHistory() *InMemoryPolicyHistory {
	return &InMemoryPolicyHistory{
		entries: make(map[string]*PolicyHistoryEntry),
	}
}

func (s *InMemoryPolicyHistory) Add(entry *PolicyHistoryEntry) string {
	if entry.ID == "" {
		entry.ID = "hist_" + uuid.New().String()[:16]
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[entry.ID] = entry
	return entry.ID
}

func (s *InMemoryPolicyHistory) Get(id string) (*PolicyHistoryEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[id]
	return entry, ok
}

func (s *InMemoryPolicyHistory) List() []*PolicyHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PolicyHistoryEntry, 0, len(s.entries))
	for _, e := range s.entries {
		result = append(result, e)
	}
	return result
}

func (s *InMemoryPolicyHistory) Latest() (*PolicyHistoryEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *PolicyHistoryEntry
	for _, e := range s.entries {
		if latest == nil || e.Timestamp.After(latest.Timestamp) {
			latest = e
		}
	}
	if latest == nil {
		return nil, false
	}
	return latest, true
}

func (s *InMemoryPolicyHistory) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*PolicyHistoryEntry)
}

type PolicyHistorySnapshotter struct {
	store *InMemoryPolicyHistory
}

func NewPolicyHistorySnapshotter() *PolicyHistorySnapshotter {
	return &PolicyHistorySnapshotter{
		store: NewInMemoryPolicyHistory(),
	}
}

func (s *PolicyHistorySnapshotter) SnapshotFromStore(store *Store, source, previousVersion, gatewayID string) string {
	rules := store.ListRules()
	entry := &PolicyHistoryEntry{
		Version:         store.Version(),
		Rules:           rules,
		RuleCount:       len(rules),
		Source:          source,
		PreviousVersion: previousVersion,
		GatewayID:       gatewayID,
	}
	return s.store.Add(entry)
}

func (s *PolicyHistorySnapshotter) Get(id string) (*PolicyHistoryEntry, bool) {
	return s.store.Get(id)
}

func (s *PolicyHistorySnapshotter) List() []*PolicyHistoryEntry {
	return s.store.List()
}

func (s *PolicyHistorySnapshotter) Latest() (*PolicyHistoryEntry, bool) {
	return s.store.Latest()
}

func (s *PolicyHistorySnapshotter) RollbackTo(id string) (*PolicyHistoryEntry, bool) {
	return s.store.Get(id)
}

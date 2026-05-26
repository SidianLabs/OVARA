package capabilities

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FileBackedHistoryStore struct {
	path        string
	file        *os.File
	mu          sync.RWMutex
	maxRecords  int
	loadedCount int
	entries     []LeaseHistoryEntry
}

func NewFileBackedHistoryStore(path string, maxRecords int) (*FileBackedHistoryStore, error) {
	if maxRecords <= 0 {
		maxRecords = 50000
	}
	store := &FileBackedHistoryStore{
		path:       path,
		maxRecords: maxRecords,
		entries:    make([]LeaseHistoryEntry, 0, maxRecords),
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for history store: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open history file: %w", err)
	}
	f.Close()

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load history store: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open history file for append: %w", err)
	}
	store.file = file

	return store, nil
}

func (s *FileBackedHistoryStore) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry LeaseHistoryEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		s.loadedCount++
		s.entries = append(s.entries, entry)
	}
	return scanner.Err()
}

func (s *FileBackedHistoryStore) Append(entry LeaseHistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(entry)
	if err == nil {
		s.file.Write(append(data, '\n'))
		s.file.Sync()
	}

	s.entries = append(s.entries, entry)
	if len(s.entries) > s.maxRecords {
		s.entries = s.entries[len(s.entries)-s.maxRecords:]
	}
}

func (s *FileBackedHistoryStore) ListByLeaseID(leaseID string) []LeaseHistoryEntry {
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

func (s *FileBackedHistoryStore) ListRecent(limit int) []LeaseHistoryEntry {
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

func (s *FileBackedHistoryStore) ListBySubject(subject string) []LeaseHistoryEntry {
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

func (s *FileBackedHistoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *FileBackedHistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([]LeaseHistoryEntry, 0, s.maxRecords)
}

func (s *FileBackedHistoryStore) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *FileBackedHistoryStore) LoadedCount() int {
	return s.loadedCount
}

func (s *FileBackedHistoryStore) FilePath() string {
	return s.path
}

func (s *FileBackedHistoryStore) Stats() (total, loaded int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries), s.loadedCount
}

func LeaseUsedEntryWithContext(leaseID, gatewayID, action, resource string) LeaseHistoryEntry {
	return LeaseHistoryEntry{
		LeaseID:   leaseID,
		Event:     "used",
		Timestamp: time.Now().UTC(),
		GatewayID: gatewayID,
		Action:    action,
		Resource:  resource,
	}
}

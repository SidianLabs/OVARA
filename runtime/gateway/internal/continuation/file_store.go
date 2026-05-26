package continuation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type FileBackedStore struct {
	*InMemoryStore
	path          string
	file          *os.File
	mu            sync.RWMutex
	maxSize       int
	loadedCount   int
	retentionDays int
	maxRecords    int
	staleIDs      []string
}

func NewFileBackedStore(path string, maxSize int) (*FileBackedStore, error) {
	return NewFileBackedStoreWithRetention(path, maxSize, 0, 0)
}

func NewFileBackedStoreWithRetention(path string, maxSize int, retentionDays int, maxRecords int) (*FileBackedStore, error) {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if maxRecords <= 0 {
		maxRecords = maxSize
	}

	store := &FileBackedStore{
		InMemoryStore: NewInMemoryStore(),
		path:          path,
		maxSize:       maxSize,
		retentionDays: retentionDays,
		maxRecords:    maxRecords,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for continuation store: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open continuation file: %w", err)
	}
	f.Close()

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load continuation store: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open continuation file for append: %w", err)
	}
	store.file = file

	return store, nil
}

func (s *FileBackedStore) load() error {
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
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if cleanup, ok := m["_cleanup"].(bool); ok && cleanup {
			if ids, ok := m["continuation_ids"].([]any); ok {
				for _, id := range ids {
					if sid, ok := id.(string); ok {
						delete(s.continuations, sid)
					}
				}
			}
			continue
		}
		var cnt Continuation
		if err := json.Unmarshal(line, &cnt); err != nil {
			continue
		}
		s.loadedCount++
		s.continuations[cnt.ContinuationID] = &cnt
	}
	return scanner.Err()
}

func (s *FileBackedStore) Create(c *Continuation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.continuations[c.ContinuationID]; exists {
		return fmt.Errorf("continuation already exists: %s", c.ContinuationID)
	}

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal continuation: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write continuation: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync continuation file: %w", err)
	}

	s.continuations[c.ContinuationID] = c
	return nil
}

func (s *FileBackedStore) Update(c *Continuation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.continuations[c.ContinuationID]; !exists {
		return fmt.Errorf("continuation not found: %s", c.ContinuationID)
	}

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal continuation: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write continuation update: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync continuation file: %w", err)
	}

	s.continuations[c.ContinuationID] = c
	return nil
}

func (s *FileBackedStore) LoadedCount() int {
	return s.loadedCount
}

func (s *FileBackedStore) FilePath() string {
	return s.path
}

func (s *FileBackedStore) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *FileBackedStore) CountByState() map[State]int {
	s.InMemoryStore.mu.RLock()
	defer s.InMemoryStore.mu.RUnlock()
	counts := make(map[State]int)
	for _, c := range s.continuations {
		counts[c.State]++
	}
	return counts
}

func (s *FileBackedStore) RetentionDays() int {
	return s.retentionDays
}

func (s *FileBackedStore) MaxRecords() int {
	return s.maxRecords
}

func (s *FileBackedStore) CurrentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.continuations)
}

func (s *FileBackedStore) Sweep() (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	ageCutoff := now.AddDate(0, 0, -s.retentionDays)

	isTerminal := func(state State) bool {
		return state == StateExecuted || state == StateDenied || state == StateExpired
	}

	var toRemove []string
	staleSet := make(map[string]bool)
	for _, cnt := range s.continuations {
		if isTerminal(cnt.State) && !cnt.CreatedAt.IsZero() && cnt.CreatedAt.Before(ageCutoff) {
			toRemove = append(toRemove, cnt.ContinuationID)
			staleSet[cnt.ContinuationID] = true
		}
	}

	if len(s.continuations)-len(toRemove) > s.maxRecords && len(toRemove) < len(s.continuations) {
		ageSorted := make([]*Continuation, 0, len(s.continuations))
		for _, cnt := range s.continuations {
			if !cnt.CreatedAt.IsZero() && !staleSet[cnt.ContinuationID] {
				ageSorted = append(ageSorted, cnt)
			}
		}
		sort.Slice(ageSorted, func(i, j int) bool {
			return ageSorted[i].CreatedAt.Before(ageSorted[j].CreatedAt)
		})
		target := s.maxRecords
		for i := 0; i < len(ageSorted)-target && i < len(ageSorted); i++ {
			if !staleSet[ageSorted[i].ContinuationID] {
				toRemove = append(toRemove, ageSorted[i].ContinuationID)
				staleSet[ageSorted[i].ContinuationID] = true
			}
		}
	}

	if len(toRemove) == 0 {
		return 0, nil
	}

	cleanup := map[string]any{"_cleanup": true, "continuation_ids": toRemove}
	data, err := json.Marshal(cleanup)
	if err == nil {
		s.file.Write(append(data, '\n'))
	}

	for _, id := range toRemove {
		delete(s.continuations, id)
	}
	s.staleIDs = append(s.staleIDs, toRemove...)

	return len(toRemove), nil
}

func (s *FileBackedStore) Compact() error {
	s.mu.Lock()
	stale := s.staleIDs
	s.mu.Unlock()

	if len(stale) == 0 {
		return nil
	}

	staleSet := make(map[string]bool, len(stale))
	for _, id := range stale {
		staleSet[id] = true
	}

	tmpPath := s.path + ".compact.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open compact tmp file: %w", err)
	}

	var keptConts []*Continuation

	s.mu.RLock()
	for _, cnt := range s.continuations {
		if staleSet[cnt.ContinuationID] {
			continue
		}
		data, err := json.Marshal(cnt)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.RUnlock()
			return fmt.Errorf("failed to marshal continuation during compact: %w", err)
		}
		if _, err := tmpFile.Write(append(data, '\n')); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.RUnlock()
			return fmt.Errorf("failed to write continuation during compact: %w", err)
		}
		keptConts = append(keptConts, cnt)
	}
	s.mu.RUnlock()

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync compact file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close compact file: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("failed to rename compact file: %w", err)
	}

	s.mu.Lock()
	for _, id := range stale {
		delete(s.continuations, id)
	}
	s.staleIDs = nil
	newFile, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to reopen continuation file after compact: %w", err)
	}
	oldFile := s.file
	s.file = newFile
	s.mu.Unlock()

	oldFile.Close()
	return nil
}

func (s *FileBackedStore) FileSizeBytes() (int64, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
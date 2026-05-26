package execution

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FileBackedStore struct {
	*InMemoryStore
	path         string
	file         *os.File
	mu           sync.Mutex
	maxSize      int
	loadedCount  int
	retentionDays int
	maxRecords   int
	staleIDs     []string
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
		maxRecords:   maxRecords,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for execution store: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open execution file: %w", err)
	}
	f.Close()

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load execution store: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open execution file for append: %w", err)
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
			if ids, ok := m["execution_ids"].([]any); ok {
				for _, id := range ids {
					if sid, ok := id.(string); ok {
						delete(s.executions, sid)
					}
				}
			}
			continue
		}
		var exe Execution
		if err := json.Unmarshal(line, &exe); err != nil {
			continue
		}
		s.loadedCount++
		s.executions[exe.ExecutionID] = &exe
	}
	return scanner.Err()
}

func (s *FileBackedStore) Create(e *Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.executions[e.ExecutionID]; exists {
		return fmt.Errorf("execution already exists: %s", e.ExecutionID)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to marshal execution: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write execution: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync execution file: %w", err)
	}

	s.executions[e.ExecutionID] = e
	return nil
}

func (s *FileBackedStore) Update(e *Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.executions[e.ExecutionID]; !exists {
		return fmt.Errorf("execution not found: %s", e.ExecutionID)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to marshal execution: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write execution update: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync execution file: %w", err)
	}

	s.executions[e.ExecutionID] = e
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

func (s *FileBackedStore) Stats() (total, succeeded, failed, running, timedOut int) {
	for _, e := range s.executions {
		total++
		switch e.State {
		case StateSucceeded:
			succeeded++
		case StateFailed:
			failed++
		case StateRunning:
			running++
		case StateTimedOut:
			timedOut++
		}
	}
	return
}

func (s *FileBackedStore) Sweep() (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	ageCutoff := now.AddDate(0, 0, -s.retentionDays)

	var toRemove []string
	for _, e := range s.executions {
		terminal := e.State == StateSucceeded || e.State == StateFailed || e.State == StateTimedOut
		if terminal && e.FinishedAt != nil && e.FinishedAt.Before(ageCutoff) {
			toRemove = append(toRemove, e.ExecutionID)
		}
	}

	if len(s.executions)-len(toRemove) > s.maxRecords && len(toRemove) < len(s.executions) {
		ageSorted := make([]*Execution, 0, len(s.executions))
		for _, e := range s.executions {
			if e.FinishedAt != nil {
				ageSorted = append(ageSorted, e)
			}
		}
		for i := 0; i < len(ageSorted)-1; i++ {
			for j := i + 1; j < len(ageSorted); j++ {
				if ageSorted[j].FinishedAt.Before(*ageSorted[i].FinishedAt) {
					ageSorted[i], ageSorted[j] = ageSorted[j], ageSorted[i]
				}
			}
		}
		target := s.maxRecords
		for i := 0; i < len(ageSorted)-target && i < len(ageSorted); i++ {
			if !containsStr(toRemove, ageSorted[i].ExecutionID) {
				toRemove = append(toRemove, ageSorted[i].ExecutionID)
			}
		}
	}

	if len(toRemove) == 0 {
		return 0, nil
	}

	cleanup := map[string]any{"_cleanup": true, "execution_ids": toRemove}
	data, err := json.Marshal(cleanup)
	if err == nil {
		s.file.Write(append(data, '\n'))
	}

	for _, id := range toRemove {
		delete(s.executions, id)
	}

	return len(toRemove), nil
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
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
	return len(s.executions)
}

func (s *FileBackedStore) Compact() error {
	s.mu.Lock()
	stale := s.staleIDs
	s.mu.Unlock()

	if len(stale) == 0 {
		return nil
	}

	s.mu.Lock()
	for _, id := range stale {
		delete(s.executions, id)
	}
	s.staleIDs = nil
	s.mu.Unlock()

	tmpPath := s.path + ".compact.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open compact tmp file: %w", err)
	}

	for _, exe := range s.executions {
		data, err := json.Marshal(exe)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to marshal execution during compact: %w", err)
		}
		if _, err := tmpFile.Write(append(data, '\n')); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write execution during compact: %w", err)
		}
	}

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
	newFile, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to reopen execution file after compact: %w", err)
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
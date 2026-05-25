package execution

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type FileBackedStore struct {
	*InMemoryStore
	path        string
	file        *os.File
	mu          sync.Mutex
	maxSize     int
	loadedCount int
}

func NewFileBackedStore(path string, maxSize int) (*FileBackedStore, error) {
	if maxSize <= 0 {
		maxSize = 10000
	}

	store := &FileBackedStore{
		InMemoryStore: NewInMemoryStore(),
		path:          path,
		maxSize:       maxSize,
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
		var exe Execution
		if err := json.Unmarshal(line, &exe); err != nil {
			continue
		}
		s.loadedCount++
		s.InMemoryStore.executions[exe.ExecutionID] = &exe
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
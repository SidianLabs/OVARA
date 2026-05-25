package continuation

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
		var cnt Continuation
		if err := json.Unmarshal(line, &cnt); err != nil {
			continue
		}
		s.loadedCount++
		s.InMemoryStore.continuations[cnt.ContinuationID] = &cnt
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
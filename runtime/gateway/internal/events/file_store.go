package events

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
	path       string
	file       *os.File
	mu         sync.Mutex
	maxEvents  int
	loadedCount int
}

func NewFileBackedStore(path string, maxEvents int) (*FileBackedStore, error) {
	if maxEvents <= 0 {
		maxEvents = 50000
	}

	store := &FileBackedStore{
		InMemoryStore: NewInMemoryStore(maxEvents),
		path:          path,
		maxEvents:     maxEvents,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for event store: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open event file: %w", err)
	}
	f.Close()

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("failed to load event store: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open event file for append: %w", err)
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
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var evt Event
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		s.loadedCount++
		s.InMemoryStore.Append(&evt)
	}
	return scanner.Err()
}

func (s *FileBackedStore) Append(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(event)
	if err == nil {
		s.file.Write(append(data, '\n'))
		s.file.Sync()
	}

	s.InMemoryStore.Append(event)
}

func (s *FileBackedStore) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *FileBackedStore) LoadedCount() int {
	return s.loadedCount
}

func (s *FileBackedStore) FilePath() string {
	return s.path
}
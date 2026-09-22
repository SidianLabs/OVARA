package execution

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ovara.runtime.gateway/internal/record"
)

// FileBackedStore appends execution records to a JSONL file while serving
// reads from an embedded in-memory index.
//
// Lock discipline: a single mutex — InMemoryStore.mu — guards BOTH the
// executions map and the append file. All map reads/writes and file appends
// happen under it (previous code used a second mutex, so file-backed writes
// raced the embedded store's lock and Stats iterated the map unlocked).
type FileBackedStore struct {
	*InMemoryStore
	path         string
	file         *os.File
	journal      *record.Journal // non-nil → signed journal mode (P2.4)
	tipsSink     func(seq uint64, hash string) error
	compactSeen  bool
	maxSize      int
	loadedCount  int
	retentionDays int
	maxRecords   int
	staleIDs     []string
}

func NewFileBackedStore(path string, maxSize int) (*FileBackedStore, error) {
	return NewFileBackedStoreWithRetention(path, maxSize, 0, 0)
}

// NewFileBackedStoreWithRetention opens the execution store. A non-nil
// record.Binding switches the file into signed-journal mode (P2.4);
// unsigned legacy files fail closed — run `gwctl migrate` first.
func NewFileBackedStoreWithRetention(path string, maxSize int, retentionDays int, maxRecords int, bindings ...*record.Binding) (*FileBackedStore, error) {
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

	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		j, err := record.Open("execution", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor, store.foldEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to fold execution journal: %w", err)
		}
		store.journal = j
		return store, nil
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

	stored := e.sanitized()
	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal execution: %w", err)
	}

	if err := s.appendLocked(e.ExecutionID, data); err != nil {
		return fmt.Errorf("failed to write execution: %w", err)
	}

	s.executions[e.ExecutionID] = stored
	return nil
}

// appendLocked writes one record line — a signed envelope in journal
// mode, raw JSON in legacy mode — and fsyncs. Callers must hold s.mu.
func (s *FileBackedStore) appendLocked(recordID string, data []byte) error {
	if s.journal != nil {
		seq, tip, err := s.journal.Append("execution", recordID, json.RawMessage(data), nil)
		if err != nil {
			return err
		}
		if s.tipsSink != nil {
			return s.tipsSink(seq, tip)
		}
		return nil
	}
	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return err
	}
	return s.file.Sync()
}

// SetTipsSink wires the committed-floor hook (gwidentity tip-ledger).
// Must be called before concurrent use.
func (s *FileBackedStore) SetTipsSink(fn func(seq uint64, hash string) error) {
	s.tipsSink = fn
}

// JournalTip exposes the journal's committed (seq, tip hash).
// Zero values in legacy mode.
func (s *FileBackedStore) JournalTip() (uint64, string) {
	if s.journal == nil {
		return 0, ""
	}
	return s.journal.Tip()
}

func (s *FileBackedStore) Update(e *Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.executions[e.ExecutionID]; !exists {
		return fmt.Errorf("execution not found: %s", e.ExecutionID)
	}

	stored := e.sanitized()
	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal execution: %w", err)
	}

	if err := s.appendLocked(e.ExecutionID, data); err != nil {
		return fmt.Errorf("failed to write execution update: %w", err)
	}

	s.executions[e.ExecutionID] = stored
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

// Stats is inherited from InMemoryStore, which takes the shared RLock — the
// previous unlocked override was removed so the map is never iterated
// without the lock.

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

	if s.journal != nil {
		data, _ := json.Marshal(map[string]any{"removed_ids": toRemove})
		if seq, tip, werr := s.journal.Append(record.TypeCompact, "",
			json.RawMessage(data), nil); werr == nil && s.tipsSink != nil {
			_ = s.tipsSink(seq, tip)
		}
		for _, id := range toRemove {
			delete(s.executions, id)
		}
		s.staleIDs = append(s.staleIDs, toRemove...)
		return len(toRemove), nil
	}

	cleanup := map[string]any{"_cleanup": true, "execution_ids": toRemove}
	data, err := json.Marshal(cleanup)
	if err == nil {
		// Tombstone must be durable: without Sync a crash can lose it and
		// swept records resurrect on reload.
		if _, werr := s.file.Write(append(data, '\n')); werr == nil {
			_ = s.file.Sync()
		}
	}

	for _, id := range toRemove {
		delete(s.executions, id)
	}
	s.staleIDs = append(s.staleIDs, toRemove...)

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

// Compact rewrites the log without stale records. The store lock is held for
// the whole read-map → write-tmp → rename → reopen sequence so no write can
// slip into the window between rename and reopen and be lost.
func (s *FileBackedStore) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.journal != nil {
		return s.compactSigned()
	}

	stale := s.staleIDs
	staleSet := make(map[string]bool, len(stale))
	for _, id := range stale {
		staleSet[id] = true
	}
	for id := range staleSet {
		delete(s.executions, id)
	}
	s.staleIDs = nil

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

	newFile, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to reopen execution file after compact: %w", err)
	}
	oldFile := s.file
	s.file = newFile
	s.mu.Unlock()

	oldFile.Close()
	s.mu.Lock()
	return nil
}

// compactSigned rewrites the journal preserving chain continuity: the
// first line is a signed compact marker carrying compacted_through +
// prior_tip, adopting the previous tip's (seq, parent) position.
func (s *FileBackedStore) compactSigned() error {
	seq, tip := s.journal.Tip()
	tmpPath := s.path + ".compact.tmp"
	w, err := record.ResumeAt("execution", tmpPath, s.journal.Domain(), s.journal.Signer(), seq, tip)
	if err != nil {
		return fmt.Errorf("compact: %w", err)
	}
	marker, _ := json.Marshal(map[string]any{
		"compacted_through": seq, "prior_tip": tip,
		"removed_ids":       s.staleIDs})
	if _, _, err := w.Append(record.TypeCompact, "", json.RawMessage(marker),
		[]record.Link{{Kind: "prior_tip", Hash: tip}}); err != nil {
		w.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("compact: marker: %w", err)
	}
	for _, exe := range s.executions {
		data, err := json.Marshal(exe)
		if err != nil {
			w.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("compact: marshal: %w", err)
		}
		if _, _, err := w.Append("execution", exe.ExecutionID, json.RawMessage(data), nil); err != nil {
			w.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("compact: record: %w", err)
		}
	}
	newSeq, newTip := w.Tip()
	if err := w.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("compact: close: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("compact: rename: %w", err)
	}
	j, err := record.ResumeAt("execution", s.path, s.journal.Domain(), s.journal.Signer(), newSeq, newTip)
	if err != nil {
		return fmt.Errorf("compact: reopen: %w", err)
	}
	_ = s.journal.Close()
	s.journal = j
	s.staleIDs = nil
	if s.tipsSink != nil {
		_ = s.tipsSink(newSeq, newTip)
	}
	return nil
}

func (s *FileBackedStore) FileSizeBytes() (int64, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

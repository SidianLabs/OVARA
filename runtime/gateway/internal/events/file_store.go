package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/record"
)

type FileBackedStore struct {
	path          string
	file          *os.File
	journal       *record.Journal // non-nil → signed journal mode (P2.4)
	tipsSink      func(seq uint64, hash string) error
	journalErr    error          // sticky append failure in journal mode
	mu            sync.RWMutex
	events        []*Event
	maxLen        int
	maxEvents     int
	loadedCount   int
	retentionDays int
	maxRecords    int
	staleEvents   []string
}

func NewFileBackedStore(path string, maxEvents int, bindings ...*record.Binding) (*FileBackedStore, error) {
	return NewFileBackedStoreWithRetention(path, maxEvents, 0, 0, bindings...)
}

// NewFileBackedStoreWithRetention opens the event store. A non-nil
// record.Binding switches it into signed-journal mode (P2.4): one signed
// envelope per event, hash-chained and domain-bound; unsigned legacy
// lines fail closed — run `gwctl migrate` first. In journal mode,
// Sweep's _cleanup pseudo-records become TypeCompact envelopes and
// file-level Compact is a no-op (sweeps are journaled deletions).
func NewFileBackedStoreWithRetention(path string, maxEvents int, retentionDays int, maxRecords int, bindings ...*record.Binding) (*FileBackedStore, error) {
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if maxRecords <= 0 {
		maxRecords = maxEvents
	}

	store := &FileBackedStore{
		path:          path,
		maxLen:        maxEvents,
		maxEvents:     maxEvents,
		retentionDays: retentionDays,
		maxRecords:    maxRecords,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for event store: %w", err)
	}

	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		j, err := record.Open("events", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor, store.foldEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to fold events journal: %w", err)
		}
		store.journal = j
		return store, nil
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
			if ids, ok := m["event_ids"].([]any); ok {
				for _, id := range ids {
					if sid, ok := id.(string); ok {
						s.staleEvents = append(s.staleEvents, sid)
					}
				}
			}
			continue
		}
		var evt Event
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		s.loadedCount++
		s.events = append(s.events, &evt)
	}
	return scanner.Err()
}

func (s *FileBackedStore) Append(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(event)
	if err == nil {
		if s.journal != nil {
			seq, tip, jerr := s.journal.Append("event", event.EventID, json.RawMessage(data), nil)
			if jerr != nil {
				s.journalErr = jerr
			} else if s.tipsSink != nil {
				s.journalErr = s.tipsSink(seq, tip)
			}
		} else {
			s.file.Write(append(data, '\n'))
			s.file.Sync()
		}
	}

	s.events = append(s.events, event)
	if len(s.events) > s.maxLen {
		s.events = s.events[len(s.events)-s.maxLen:]
	}
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

// LastError surfaces the sticky journal-append failure — Append's
// frozen signature returns nothing, so audit-path failures land here.
func (s *FileBackedStore) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.journalErr
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

func (s *FileBackedStore) RetentionDays() int {
	return s.retentionDays
}

func (s *FileBackedStore) MaxRecords() int {
	return s.maxRecords
}

func (s *FileBackedStore) CurrentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *FileBackedStore) Sweep() (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	ageCutoff := now.AddDate(0, 0, -s.retentionDays)

	var toRemove []string
	staleSet := make(map[string]bool)
	for _, evt := range s.events {
		if !evt.Timestamp.IsZero() && evt.Timestamp.Before(ageCutoff) {
			toRemove = append(toRemove, evt.EventID)
			staleSet[evt.EventID] = true
		}
	}

	if len(s.events)-len(toRemove) > s.maxRecords && len(toRemove) < len(s.events) {
		ageSorted := make([]*Event, 0, len(s.events))
		for _, evt := range s.events {
			if !evt.Timestamp.IsZero() && !staleSet[evt.EventID] {
				ageSorted = append(ageSorted, evt)
			}
		}
		sort.Slice(ageSorted, func(i, j int) bool {
			return ageSorted[i].Timestamp.Before(ageSorted[j].Timestamp)
		})
		target := s.maxRecords
		for i := 0; i < len(ageSorted)-target && i < len(ageSorted); i++ {
			if !staleSet[ageSorted[i].EventID] {
				toRemove = append(toRemove, ageSorted[i].EventID)
				staleSet[ageSorted[i].EventID] = true
			}
		}
	}

	if len(toRemove) == 0 {
		return 0, nil
	}

	cleanup := map[string]any{"_cleanup": true, "event_ids": toRemove}
	data, err := json.Marshal(cleanup)
	if err == nil {
		if s.journal != nil {
			cc, _ := json.Marshal(map[string]any{"removed_ids": toRemove})
			seq, tip, jerr := s.journal.Append(record.TypeCompact, "", json.RawMessage(cc), nil)
			if jerr != nil {
				s.mu.Unlock()
				return 0, jerr
			}
			if s.tipsSink != nil {
				_ = s.tipsSink(seq, tip)
			}
		} else {
			// Tombstone must be durable: without Sync a crash can lose it and
			// swept events resurrect on reload.
			if _, werr := s.file.Write(append(data, '\n')); werr == nil {
				_ = s.file.Sync()
			}
		}
	}

	s.staleEvents = append(s.staleEvents, toRemove...)
	s.removeByIDsInMemory(toRemove)
	return len(toRemove), nil
}

func (s *FileBackedStore) removeByIDsInMemory(ids []string) {
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	kept := 0
	for _, evt := range s.events {
		if !idSet[evt.EventID] {
			s.events[kept] = evt
			kept++
		}
	}
	s.events = s.events[:kept]
}

func (s *FileBackedStore) Compact() error {
	if s.journal != nil {
		// ponytail: file-level rewrite would orphan envelopes the journal
		// fold still re-verifies; swept rows are already durable
		// TypeCompact deletions, so compaction is a no-op in journal mode.
		return nil
	}
	s.mu.Lock()
	stale := s.staleEvents
	staleSet := make(map[string]bool, len(stale))
	for _, id := range stale {
		staleSet[id] = true
	}
	keptEvents := make([]*Event, 0, len(s.events)-len(stale))
	for _, evt := range s.events {
		if staleSet[evt.EventID] {
			continue
		}
		keptEvents = append(keptEvents, evt)
	}

	tmpPath := s.path + ".compact.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to open compact tmp file: %w", err)
	}

	for _, evt := range keptEvents {
		data, err := json.Marshal(evt)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.Unlock()
			return fmt.Errorf("failed to marshal event during compact: %w", err)
		}
		if _, err := tmpFile.Write(append(data, '\n')); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.Unlock()
			return fmt.Errorf("failed to write event during compact: %w", err)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		s.mu.Unlock()
		return fmt.Errorf("failed to sync compact file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		s.mu.Unlock()
		return fmt.Errorf("failed to close compact file: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to rename compact file: %w", err)
	}

	newFile, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to reopen event file after compact: %w", err)
	}
	oldFile := s.file
	s.file = newFile
	s.events = keptEvents
	s.staleEvents = nil
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

func (s *FileBackedStore) List(limit int) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	staleSet := make(map[string]bool, len(s.staleEvents))
	for _, id := range s.staleEvents {
		staleSet[id] = true
	}

	var result []*Event
	count := 0
	for i := len(s.events) - 1; i >= 0; i-- {
		evt := s.events[i]
		if staleSet[evt.EventID] {
			continue
		}
		result = append(result, evt)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}

	reversed := make([]*Event, len(result))
	for i, j := 0, len(result)-1; i <= j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = result[j], result[i]
	}
	return reversed
}

func (s *FileBackedStore) Get(eventID string) (*Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	staleSet := make(map[string]bool, len(s.staleEvents))
	for _, id := range s.staleEvents {
		staleSet[id] = true
	}
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].EventID == eventID {
			if staleSet[eventID] {
				return nil, false
			}
			cp := *s.events[i]
			return &cp, true
		}
	}
	return nil, false
}

func (s *FileBackedStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *FileBackedStore) Stats() (total, cleanupPending int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events), len(s.staleEvents)
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

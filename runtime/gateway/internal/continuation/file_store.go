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
	path          string
	file          *os.File
	mu            sync.RWMutex
	continuations map[string]*Continuation
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
		path:          path,
		maxSize:       maxSize,
		retentionDays: retentionDays,
		maxRecords:    maxRecords,
		continuations: make(map[string]*Continuation),
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

func (s *FileBackedStore) Get(id string) (*Continuation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.continuations[id]
	return c, ok
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

func (s *FileBackedStore) ListByState(state State) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.State == state {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *FileBackedStore) ListByDecision(decisionID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.DecisionID == decisionID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *FileBackedStore) ListByAgent(agentID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.AgentID == agentID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *FileBackedStore) ListByApprovalID(approvalID string) []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if c.ApprovalID == approvalID {
			result = append(result, c.snapshot())
		}
	}
	return result
}

func (s *FileBackedStore) ListAll() []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		result = append(result, c.snapshot())
	}
	return result
}

func (s *FileBackedStore) ListNonTerminal() []*Continuation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Continuation
	for _, c := range s.continuations {
		if !c.IsTerminal() {
			result = append(result, c)
		}
	}
	return result
}

// ClaimForExecution atomically transitions an executable continuation into
// StateExecuting. Accepts Approved, Queued, Ready, or Resumed. Returns a
// snapshot (taken under the store lock) so the caller can read fields without
// racing concurrent mutations.
func (s *FileBackedStore) ClaimForExecution(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State == StateExecuting {
		return nil, false
	}
	if c.State == StateApproved || c.State == StateQueued || c.State == StateResumed {
		c.State = StateExecuting
		return c.snapshot(), true
	}
	return nil, false
}

// ClaimForRetry atomically transitions a Resumed continuation into
// StateExecuting. Returns a snapshot.
func (s *FileBackedStore) ClaimForRetry(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State == StateExecuting {
		return nil, false
	}
	if c.State == StateResumed {
		c.State = StateExecuting
		return c.snapshot(), true
	}
	return nil, false
}

// RecoverFromExecuting atomically transitions an Executing continuation back
// to StateExecuted so it becomes retryable. Used for operator-driven recovery
// of stuck executions. Persists the transition inline (cannot call Update:
// it re-locks s.mu).
func (s *FileBackedStore) RecoverFromExecuting(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State != StateExecuting {
		return nil, false
	}
	c.State = StateExecuted
	if data, err := json.Marshal(c); err == nil {
		if _, werr := s.file.Write(append(data, '\n')); werr == nil {
			_ = s.file.Sync()
		}
	}
	return c.snapshot(), true
}

// ListExecutingIDs returns the IDs of all continuations currently in
// StateExecuting. Used by operator recovery flows to enumerate stuck work
// without exposing the full continuations payload.
func (s *FileBackedStore) ListExecutingIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0)
	for id, c := range s.continuations {
		if c.State == StateExecuting {
			ids = append(ids, id)
		}
	}
	return ids
}

// RetryForExecution atomically transitions an executed/resumed continuation
// into a retry (StateResumed, RetryCount incremented) when retries remain.
// The whole check-and-mutate happens under the store lock so concurrent
// retry callers (e.g. single retry vs bulk retry) cannot double-apply.
func (s *FileBackedStore) RetryForExecution(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if c.State != StateExecuted && c.State != StateResumed {
		return nil, false
	}
	if c.MaxRetries <= 0 {
		return nil, false
	}
	if c.RetryCount >= c.MaxRetries {
		return nil, false
	}
	c.State = StateResumed
	c.RetryCount++
	now := time.Now().UTC()
	c.ResumedAt = &now

	// Persist the retry transition inline (cannot call Update: it re-locks s.mu).
	// A best-effort write keeps the incremented RetryCount durable across restarts;
	// the in-memory transition has already been applied under the lock.
	if data, err := json.Marshal(c); err == nil {
		if _, werr := s.file.Write(append(data, '\n')); werr == nil {
			_ = s.file.Sync()
		}
	}
	return c.snapshot(), true
}

// CancelForOperation atomically cancels a cancellable continuation under the
// store lock and returns a snapshot. The cancel transition is persisted inline
// so it survives restarts.
func (s *FileBackedStore) CancelForOperation(id string) (*Continuation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.continuations[id]
	if !ok {
		return nil, false
	}
	if !c.CanCancel() {
		return nil, false
	}
	c.MarkCancelled()
	if data, err := json.Marshal(c); err == nil {
		if _, werr := s.file.Write(append(data, '\n')); werr == nil {
			_ = s.file.Sync()
		}
	}
	return c.snapshot(), true
}

func (s *FileBackedStore) CountByState() map[State]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[State]int)
	for _, c := range s.continuations {
		counts[c.State]++
	}
	return counts
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
	staleSet := make(map[string]bool, len(stale))
	for _, id := range stale {
		staleSet[id] = true
	}
	keptConts := make([]*Continuation, 0, len(s.continuations)-len(stale))
	for _, cnt := range s.continuations {
		if staleSet[cnt.ContinuationID] {
			continue
		}
		keptConts = append(keptConts, cnt)
	}

	tmpPath := s.path + ".compact.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to open compact tmp file: %w", err)
	}

	for _, cnt := range keptConts {
		data, err := json.Marshal(cnt)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.Unlock()
			return fmt.Errorf("failed to marshal continuation during compact: %w", err)
		}
		if _, err := tmpFile.Write(append(data, '\n')); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			s.mu.Unlock()
			return fmt.Errorf("failed to write continuation during compact: %w", err)
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
		return fmt.Errorf("failed to reopen continuation file after compact: %w", err)
	}
	oldFile := s.file
	s.file = newFile
	s.continuations = make(map[string]*Continuation)
	for _, cnt := range keptConts {
		s.continuations[cnt.ContinuationID] = cnt
	}
	s.staleIDs = nil
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

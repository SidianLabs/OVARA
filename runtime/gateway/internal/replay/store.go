// Package replay provides the durable consume-record store behind
// replay protection (P2.1 / I11).
//
// Security property: for a valid capability presentation id,
// Consume returns FIRST_CONSUME at most once within the record's
// expiry across the trusted gateway state domain — where "trusted
// gateway state domain" is defined as the set of gateway processes
// sharing one replay journal file on a single filesystem (flock
// scope). Two gateways on different filesystems are different
// domains; there is no cross-host replication in P2.1.
//
// The store is an append-only JSONL journal guarded by flock(LOCK_EX):
// check + insert are atomic for every process holding the lock.
// Records are durable before Consume returns FIRST_CONSUME (fsync
// precedes the return), so a crash cannot resurrect a consumed id.
package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/record"
)

type Result int

const (
	FirstConsume Result = iota
	AlreadyConsumed
	StorageFailure
)

// Kind namespaces replay identifiers so a client-chosen request nonce
// can never collide with a canonical delegation replay key (the two
// were deliberately separate maps in the in-memory implementation for
// the same reason).
type Kind string

const (
	KindRequest    Kind = "req"
	KindDelegation Kind = "deleg"
)

// Store is the consume abstraction. Implementations must guarantee
// that two concurrent Consume calls for the same live id never both
// return FIRST_CONSUME.
type Store interface {
	Consume(kind Kind, id string, expiresAt time.Time) Result
	Close() error
}

// record is one journal line. Zero ExpiresAt = permanent record (an
// unbounded capability needs unbounded replay state).
type entry struct {
	Kind       string    `json:"k"`
	ID         string    `json:"p"`
	ConsumedAt time.Time `json:"c"`
	ExpiresAt  time.Time `json:"e,omitempty"`
}

func key(kind Kind, id string) string { return string(kind) + "\x00" + id }

func live(exp time.Time, now time.Time) bool {
	return exp.IsZero() || now.Before(exp)
}

// FileStore is a single-journal durable store. A consume is one
// O_APPEND write + fsync. Replays are memory-only lookups. Processes
// sharing the file coordinate via flock + tail-read: before deciding
// FIRST_CONSUME the process absorbs journal bytes appended since its
// last read, so another process's consume is never missed.
type FileStore struct {
	f        *os.File
	journal  *record.Journal // non-nil → signed journal mode (P2.4)
	tipsSink func(seq uint64, hash string) error
	mu       sync.Mutex
	seen     map[string]time.Time
	offset   int64
	maxBytes int64
}

// OpenFile opens (creating) the journal at path. In legacy mode a
// corrupt tail — possible after a crash between write and fsync — is
// truncated to the last good record; corruption anywhere else fails
// open: the store cannot prove its replay state, so the caller must
// fail closed. A non-nil
// record.Binding switches it into signed-journal mode (P2.4): every
// consume record is a domain-bound signed envelope, tail-absorb
// re-verifies chain continuity, and unsigned/corrupt history fails
// closed. Multi-process sharing still works — every Consume re-absorbs
// under flock and appends on top of the absorbed tip. Compaction is
// disabled in signed mode (a rewrite would fork sibling processes'
// absorbed chains); the journal grows bounded by capability volume.
func OpenFile(path string, maxBytes int64, bindings ...*record.Binding) (*FileStore, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("replay store: mkdir: %w", err)
	}
	var binding *record.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	if binding != nil {
		s := &FileStore{seen: make(map[string]time.Time), maxBytes: maxBytes}
		j, err := record.Open("replay", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor, s.foldEnvelope)
		if err != nil {
			return nil, fmt.Errorf("replay store: fold: %w", err)
		}
		s.f = j.File()
		s.journal = j
		return s, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("replay store: open %s: %w", path, err)
	}
	s := &FileStore{f: f, seen: make(map[string]time.Time), maxBytes: maxBytes}
	// flock the initial load too — another process may compact mid-read.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("replay store: lock: %w", err)
	}
	err = s.absorb()
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// foldEnvelope applies one verified envelope to the seen map.
func (s *FileStore) foldEnvelope(env *record.Envelope) error {
	if env.Type == record.TypeMigration {
		return nil // provenance marker
	}
	if env.Type != "consume" {
		return fmt.Errorf("unknown record type %q", env.Type)
	}
	var r entry
	if err := json.Unmarshal(env.Payload, &r); err != nil {
		return fmt.Errorf("corrupt consume payload: %w", err)
	}
	if live(r.ExpiresAt, time.Now().UTC()) {
		s.seen[key(Kind(r.Kind), r.ID)] = r.ExpiresAt
	}
	return nil
}

// SetTipsSink wires the committed-floor hook (gwidentity tip-ledger).
// Must be called before concurrent use.
func (s *FileStore) SetTipsSink(fn func(seq uint64, hash string) error) {
	s.tipsSink = fn
}

// JournalTip exposes the journal's committed (seq, tip hash).
// Zero values in legacy mode.
func (s *FileStore) JournalTip() (uint64, string) {
	if s.journal == nil {
		return 0, ""
	}
	return s.journal.Tip()
}

// absorb reads journal bytes appended since s.offset into the live
// map. Must be called with flock held (or at open before sharing).
// A journal smaller than s.offset means another process compacted it:
// compaction preserves all live records, so resetting and reloading
// from zero is lossless.
func (s *FileStore) absorb() error {
	st, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("replay store: stat: %w", err)
	}
	if st.Size() < s.offset {
		s.seen = make(map[string]time.Time)
		s.offset = 0
	}
	if st.Size() == s.offset {
		return nil
	}
	buf := make([]byte, st.Size()-s.offset)
	if _, err := s.f.ReadAt(buf, s.offset); err != nil {
		return fmt.Errorf("replay store: read: %w", err)
	}
	now := time.Now().UTC()
	pos := int64(0)
	for pos < int64(len(buf)) {
		nl := pos
		for nl < int64(len(buf)) && buf[nl] != '\n' {
			nl++
		}
		line := buf[pos:nl]
		if len(line) == 0 {
			pos = nl + 1
			continue
		}
		var r entry
		if err := json.Unmarshal(line, &r); err != nil {
			// Corrupt TAIL: a crash between write and fsync can leave a
			// partial final line. It was never a confirmed consume —
			// truncate it and continue.
			if nl == int64(len(buf)) {
				if err := s.f.Truncate(s.offset + pos); err != nil {
					return fmt.Errorf("replay store: truncate corrupt tail: %w", err)
				}
				s.offset += pos
				return nil
			}
			return fmt.Errorf("replay store: corrupt record at offset %d: %w", s.offset+pos, err)
		}
		if live(r.ExpiresAt, now) {
			s.seen[key(Kind(r.Kind), r.ID)] = r.ExpiresAt
		}
		pos = nl + 1
	}
	s.offset += int64(len(buf))
	return nil
}

// compact rewrites the journal keeping only live records. Caller holds
// s.mu and flock. Bounds journal growth; correctness never depends on
// compaction timing (expired records are harmless to keep).
func (s *FileStore) compact() error {
	lines := make([]byte, 0, len(s.seen)*128)
	now := time.Now().UTC()
	for k, exp := range s.seen {
		if !live(exp, now) {
			delete(s.seen, k)
			continue
		}
		idx := 0
		for idx < len(k) && k[idx] != 0 {
			idx++
		}
		data, err := json.Marshal(entry{Kind: k[:idx], ID: k[idx+1:], ConsumedAt: now, ExpiresAt: exp})
		if err != nil {
			return fmt.Errorf("replay store: compact marshal: %w", err)
		}
		lines = append(lines, data...)
		lines = append(lines, '\n')
	}
	// Truncate+rewrite on a SEPARATE non-append fd: O_APPEND ignores
	// WriteAt offsets. Truncating in place (not rename) keeps the inode
	// — every other process's fd and our own O_APPEND writes stay valid.
	cf, err := os.OpenFile(s.f.Name(), os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("replay store: compact open: %w", err)
	}
	defer cf.Close()
	if err := cf.Truncate(0); err != nil {
		return fmt.Errorf("replay store: compact truncate: %w", err)
	}
	if _, err := cf.WriteAt(lines, 0); err != nil {
		return fmt.Errorf("replay store: compact write: %w", err)
	}
	if err := cf.Sync(); err != nil {
		return fmt.Errorf("replay store: compact sync: %w", err)
	}
	s.offset = int64(len(lines))
	return nil
}

// Consume implements Store. FIRST_CONSUME is returned only after the
// record is fsynced — a crash after this point cannot lose it.
func (s *FileStore) Consume(kind Kind, id string, expiresAt time.Time) Result {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Fast path: a live record in memory is already durable — it was
	// added only after fsync succeeded, here or by a tail-read.
	if exp, ok := s.seen[key(kind, id)]; ok && live(exp, now) {
		return AlreadyConsumed
	}

	if err := syscall.Flock(int(s.f.Fd()), syscall.LOCK_EX); err != nil {
		return StorageFailure
	}
	defer syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN)

	if s.journal == nil {
		if err := s.absorb(); err != nil {
			return StorageFailure
		}
		if exp, ok := s.seen[key(kind, id)]; ok && live(exp, now) {
			return AlreadyConsumed
		}
	}
	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		// Already-expired capability reaching consume is meaningless —
		// treat as consumed-needing-no-record. Validation upstream
		// denies expired artifacts before this point regardless.
		return FirstConsume
	}
	if s.journal != nil {
		// Signed mode: absorb siblings' committed records (verifying
		// each envelope), then append on top of the true tip. A forked
		// chain surfaces as a parent mismatch → StorageFailure, never
		// a silently-diverged consume.
		if err := s.journal.Absorb(); err != nil {
			return StorageFailure
		}
		if exp, ok := s.seen[key(kind, id)]; ok && live(exp, now) {
			return AlreadyConsumed
		}
		payload, err := json.Marshal(entry{Kind: string(kind), ID: id, ConsumedAt: now, ExpiresAt: expiresAt})
		if err != nil {
			return StorageFailure
		}
		seq, tip, err := s.journal.Append("consume", key(kind, id), json.RawMessage(payload), nil)
		if err != nil {
			return StorageFailure
		}
		if s.tipsSink != nil && s.tipsSink(seq, tip) != nil {
			return StorageFailure
		}
		s.seen[key(kind, id)] = expiresAt
		// Compaction deliberately skipped in signed mode — rewriting
		// the file would invalidate sibling processes' absorbed chains.
		return FirstConsume
	}
	data, err := json.Marshal(entry{Kind: string(kind), ID: id, ConsumedAt: now, ExpiresAt: expiresAt})
	if err != nil {
		return StorageFailure
	}
	data = append(data, '\n')
	if _, err := s.f.Write(data); err != nil {
		return StorageFailure
	}
	if err := s.f.Sync(); err != nil {
		return StorageFailure
	}
	s.offset += int64(len(data))
	s.seen[key(kind, id)] = expiresAt
	if s.offset > s.maxBytes {
		// Compaction failure only delays cleanup — the journal stays
		// correct, just larger. Report storage failure so the caller
		// fails closed rather than growing silently.
		if err := s.compact(); err != nil {
			return StorageFailure
		}
	}
	return FirstConsume
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

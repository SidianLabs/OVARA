// Package audit implements OVARA v2's evidence log: an append-only,
// hash-chained, Ed25519-signed record store with signed Merkle
// checkpoints anchored off-host. Write-ahead: Append returns only
// after the record is durably flushed — an executor that gates on
// Append satisfies P7 (executed implies durable log entry).
//
// Deviations from v1 receipts, by design:
//   - checkpoints are signed Merkle roots over the full record set,
//     not unsigned head-hash snapshots (SEC-0003).
//   - checkpoint anchors are pushed to an external sink, not written
//     beside the log (SEC-0003 co-location).
//   - verify requires an explicitly-supplied trusted key; no silent
//     sibling-file fallback (SEC-0002).
//   - every record carries seq + monotonic timestamp; truncation and
//     reordering are both checkpoint-visible.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Record is one log entry. Payload is the canonical JSON encoding of
// the typed record (decision, execution, checkpoint marker); the log
// does not interpret it.
type Record struct {
	Seq      uint64    `json:"seq"`
	RecordID string    `json:"record_id"`
	Type     string    `json:"type"` // decision | execution | event
	Payload  []byte    `json:"payload"`
	PrevHash string    `json:"prev_hash"`
	Timestamp time.Time `json:"timestamp"`
	Hash     string    `json:"hash"`
	Sig      string    `json:"sig"` // edsig_v2:<hex ed25519>
}

// canonical returns the pipe-delimited signing payload. Every field
// that affects integrity is inside it.
func (r *Record) canonical() string {
	return fmt.Sprintf("%d|%s|%s|%x|%s|%d|%s",
		r.Seq, r.RecordID, r.Type, sha256.Sum256(r.Payload),
		r.PrevHash, r.Timestamp.UnixNano(), r.Hash)
}

// computeHash is the chain hash: sha256 over the record minus sig.
func computeHash(seq uint64, id, typ string, payload []byte, prev string, ts time.Time) string {
	body := fmt.Sprintf("%d|%s|%s|%x|%s|%d",
		seq, id, typ, sha256.Sum256(payload), prev, ts.UnixNano())
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// AnchorSink receives signed checkpoints off the log's own storage.
// Implementations must not store on the same trust boundary as the
// log itself.
type AnchorSink interface {
	Put(cp Checkpoint) error
}

// FileSink writes checkpoints to a directory — suitable for a
// different host/path than the log (mounted share, operator host).
type FileSink struct{ Dir string }

func (f FileSink) Put(cp Checkpoint) error {
	b, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	name := filepath.Join(f.Dir, fmt.Sprintf("checkpoint_%d_%d.json", cp.TreeSize, cp.Epoch))
	return os.WriteFile(name, b, 0o644)
}

// Log is the append-only writer.
type Log struct {
	mu        sync.Mutex
	key       ed25519.PrivateKey
	path      string
	seq       uint64
	prevHash  string
	hashes    [][]byte // leaf hashes for Merkle roots
	epoch     uint64
	sink      AnchorSink
	cpEvery   int      // checkpoint every N records; 0 = only explicit
	sinceCp   int
}

// Open loads or creates a log. A corrupt tail is a hard error — the
// log never silently forks around unparseable data.
func Open(path string, key ed25519.PrivateKey, sink AnchorSink, cpEvery int) (*Log, error) {
	l := &Log{key: key, path: path, sink: sink, cpEvery: cpEvery,
		prevHash: strings.Repeat("0", 64)}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []Record
	dec := json.NewDecoder(f)
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("audit: corrupt tail at seq %d: %w (refusing to fork)", l.seq, err)
		}
		recs = append(recs, r)
	}
	// verify the loaded chain before appending to it
	if err := verifyRecords(recs, l.key.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("audit: existing log failed self-verify: %w", err)
	}
	for _, r := range recs {
		h, _ := hex.DecodeString(r.Hash)
		l.hashes = append(l.hashes, h)
		l.seq = r.Seq
		l.prevHash = r.Hash
	}
	return l, nil
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func NewID() string {
	var b [8]byte
	rand.Read(b[:])
	return "rec_" + hex.EncodeToString(b[:])
}

// Append writes a record and fsyncs before returning. Callers must
// treat a returned error as "not durably logged" — never proceed with
// the gated action.
func (l *Log) Append(typ string, payload []byte) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Record{
		Seq:       l.seq + 1,
		RecordID:  NewID(),
		Type:      typ,
		Payload:   payload,
		PrevHash:  l.prevHash,
		Timestamp: time.Now().UTC(),
	}
	r.Hash = computeHash(r.Seq, r.RecordID, r.Type, r.Payload, r.PrevHash, r.Timestamp)
	sig := ed25519.Sign(l.key, []byte(r.canonical()))
	r.Sig = "edsig_v2:" + hex.EncodeToString(sig)

	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return Record{}, err
	}
	b, _ := json.Marshal(r)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return Record{}, fmt.Errorf("audit: write failed: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return Record{}, fmt.Errorf("audit: flush failed: %w", err)
	}
	f.Close()

	h, _ := hex.DecodeString(r.Hash)
	l.hashes = append(l.hashes, h)
	l.seq, l.prevHash = r.Seq, r.Hash
	l.sinceCp++
	if l.cpEvery > 0 && l.sinceCp >= l.cpEvery {
		if _, err := l.emitCheckpointLocked(); err != nil {
			return r, fmt.Errorf("audit: record %d written but checkpoint failed: %w", r.Seq, err)
		}
	}
	return r, nil
}

// SetEpoch sets the revocation epoch carried into future checkpoints.
func (l *Log) SetEpoch(e uint64) { l.mu.Lock(); l.epoch = e; l.mu.Unlock() }
func (l *Log) Seq() uint64       { l.mu.Lock(); defer l.mu.Unlock(); return l.seq }

// Checkpoint forces a signed checkpoint + anchor push.
func (l *Log) Checkpoint() (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.emitCheckpointLocked()
}

func (l *Log) emitCheckpointLocked() (Checkpoint, error) {
	cp := Checkpoint{
		TreeSize: l.seq,
		RootHash: merkleRoot(l.hashes),
		Epoch:    l.epoch,
		TS:       time.Now().UTC(),
	}
	cp.Sig = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(l.key, []byte(cp.canonical())))
	if l.sink != nil {
		if err := l.sink.Put(cp); err != nil {
			return cp, fmt.Errorf("audit: anchor push failed: %w", err)
		}
	}
	l.sinceCp = 0
	return cp, nil
}

// merkleRoot builds a binary Merkle root over leaf hashes. Odd
// leaves duplicate at each level (RFC-6962-style for a static set).
func merkleRoot(leaves [][]byte) string {
	if len(leaves) == 0 {
		return strings.Repeat("0", 64)
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			l := level[i]
			r := l
			if i+1 < len(level) {
				r = level[i+1]
			}
			sum := sha256.Sum256(append(append([]byte{}, l...), r...))
			next = append(next, sum[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

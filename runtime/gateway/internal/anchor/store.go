// Oracle-side durable compare-and-store (P2.3.3 AM-6).
//
// The store is the monotonic authority: it decides whether a checkpoint
// may advance a domain's anchored sequence. Durability is a security
// requirement — in-memory state is never sufficient, an ack is never
// sent before fsync, and a torn tail truncates (never committed).
//
// Restoring this store from an older backup is an authority-recovery
// event, not crash recovery: the store never silently reinitializes a
// domain (ErrDomainUnregistered is fail-closed, not a bootstrap path),
// and joint registry+oracle co-rollback remains the documented
// anchor-compromise residual.
package anchor

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	ErrDomainUnregistered = errors.New("anchor: domain not registered")
	ErrDomainRegistered   = errors.New("anchor: domain already registered")
	ErrRegression         = errors.New("anchor: checkpoint sequence regression")
	ErrEquivocation       = errors.New("anchor: same sequence, different state")
	ErrBadKey             = errors.New("anchor: key not in domain lineage")
)

// domainState is the oracle's per-domain authoritative record.
type domainState struct {
	Checkpoint *Checkpoint       // latest stored checkpoint
	Lineage    map[string]string // pubkey hex → key_id label
}

// lineRecord is one append-only store line.
type lineRecord struct {
	Kind   string      `json:"kind"` // register|commit|key|reset
	Domain string      `json:"domain_id"`
	CP     *Checkpoint `json:"checkpoint,omitempty"`
	PubKey string      `json:"pubkey,omitempty"` // register/key records
	KeyID  string      `json:"key_id,omitempty"`
	// IntroducerSig persists the lineage-signed key-introduction proof so
	// fold can re-verify it — the trust root stays outside the record.
	IntroducerSig string `json:"introducer_sig,omitempty"`
}

// Store is the oracle's durable state: one JSONL file, flock-serialized,
// fsync-before-ack. The file's owner-only permissions are the storage
// boundary — same enforcement as the gateway registry.
type Store struct {
	mu      sync.Mutex
	f       *os.File
	off     int64
	domains map[string]*domainState
}

// OpenStore loads or creates the oracle store at path (0600 enforced).
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("anchor store: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("anchor store: open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("anchor store: %s has unsafe permissions %o — must be owner-only (0600)", path, st.Mode().Perm())
	}
	s := &Store{f: f, domains: map[string]*domainState{}}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("anchor store: lock: %w", err)
	}
	err = s.absorb()
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// absorb folds store lines appended since s.off. Corrupt non-tail
// records fail; a torn tail truncates; shrink below committed offset
// fails closed (in-process rewrite detection, same model as gwidentity).
func (s *Store) absorb() error {
	st, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("anchor store: stat: %w", err)
	}
	if st.Size() < s.off {
		return fmt.Errorf("anchor store: file shrank below committed offset %d (size %d) — history rewritten", s.off, st.Size())
	}
	if st.Size() == s.off {
		return nil
	}
	buf := make([]byte, st.Size()-s.off)
	if _, err := s.f.ReadAt(buf, s.off); err != nil {
		return fmt.Errorf("anchor store: read: %w", err)
	}
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
		var lr lineRecord
		if err := json.Unmarshal(line, &lr); err != nil {
			if nl == int64(len(buf)) {
				if err := s.f.Truncate(s.off + pos); err != nil {
					return fmt.Errorf("anchor store: truncate torn tail: %w", err)
				}
				s.off += pos
				return nil
			}
			return fmt.Errorf("anchor store: corrupt record at offset %d: %w", s.off+pos, err)
		}
		if err := s.fold(&lr); err != nil {
			return fmt.Errorf("anchor store: fold at offset %d: %w", s.off+pos, err)
		}
		pos = nl + 1
	}
	s.off += int64(len(buf))
	return nil
}

// fold applies a store line to the in-memory index, re-checking BOTH
// the monotonic invariant AND the cryptographic proofs — a folded
// record with a bad signature is corrupt store state, not merely a
// sequence violation (F-A1: the store never serves a checkpoint its
// lineage cannot verify).
func (s *Store) fold(lr *lineRecord) error {
	switch lr.Kind {
	case "register":
		if lr.CP == nil || lr.PubKey == "" || lr.Domain == "" {
			return fmt.Errorf("malformed register record")
		}
		if _, ok := s.domains[lr.Domain]; ok {
			return fmt.Errorf("duplicate domain registration %s", lr.Domain)
		}
		pub, err := hex.DecodeString(lr.PubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("register record: bad pubkey")
		}
		if err := lr.CP.Verify(ed25519.PublicKey(pub)); err != nil {
			return fmt.Errorf("register record: genesis signature invalid: %w", err)
		}
		s.domains[lr.Domain] = &domainState{Checkpoint: lr.CP,
			Lineage: map[string]string{lr.PubKey: lr.KeyID}}
	case "commit":
		if lr.CP == nil || lr.Domain == "" {
			return fmt.Errorf("malformed commit record")
		}
		d := s.domains[lr.Domain]
		if d == nil {
			return fmt.Errorf("commit to unregistered domain %s", lr.Domain)
		}
		if lr.CP.Seq <= d.Checkpoint.Seq {
			return fmt.Errorf("store regression: %s seq %d <= %d", lr.Domain, lr.CP.Seq, d.Checkpoint.Seq)
		}
		if err := verifyLineage(d, lr.CP); err != nil {
			return fmt.Errorf("commit record: %w", err)
		}
		d.Checkpoint = lr.CP
	case "key":
		d := s.domains[lr.Domain]
		if d == nil {
			return fmt.Errorf("key record for unregistered domain %s", lr.Domain)
		}
		pub, err := hex.DecodeString(lr.PubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("key record: bad pubkey")
		}
		sig, err := hex.DecodeString(lr.IntroducerSig)
		if err != nil || !introducedByLineage(d, lr.Domain, lr.KeyID, pub, sig) {
			return fmt.Errorf("key record: introduction not authorized by lineage")
		}
		d.Lineage[lr.PubKey] = lr.KeyID
	case "reset":
		delete(s.domains, lr.Domain)
	default:
		return fmt.Errorf("unknown record kind %q", lr.Kind)
	}
	return nil
}

// introducedByLineage reports whether some existing lineage key signed
// the canonical introduction of (domain, keyID, newPub) — used at both
// request time and fold time so a forged key record cannot self-authorize.
func introducedByLineage(d *domainState, domain, keyID string, newPub ed25519.PublicKey, sig []byte) bool {
	msg := KeyIntroMessage(domain, keyID, newPub)
	for pubHex := range d.Lineage {
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return true
		}
	}
	return false
}

// mutate is the serialized unit: process mutex → flock → absorb →
// check+produce (fn runs against FRESH state) → write → fsync → fold.
// The security decision can never race the write: a record that would
// violate the monotonic invariant is never appended.
func (s *Store) mutate(fn func() (*lineRecord, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := syscall.Flock(int(s.f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("anchor store: lock: %w", err)
	}
	defer syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN)
	if err := s.absorb(); err != nil {
		return err
	}
	lr, err := fn()
	if err != nil || lr == nil {
		return err
	}
	data, err := json.Marshal(lr)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := s.f.Write(data); err != nil {
		return fmt.Errorf("anchor store: append: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("anchor store: fsync: %w", err)
	}
	s.off += int64(len(data))
	return s.fold(lr)
}

// verifyLineage checks the checkpoint signature under ANY currently
// registered lineage pubkey (key_id is provenance metadata; the
// security check is sig-under-a-lineage-key).
func verifyLineage(d *domainState, cp *Checkpoint) error {
	for pubHex := range d.Lineage {
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if cp.Verify(ed25519.PublicKey(pub)) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: no lineage key verifies this checkpoint", ErrBadKey)
}

// Register performs explicit domain initialization — the ONLY way a
// domain comes to exist. cp is the genesis checkpoint, signed by the
// genesis key whose pubkey is presented and registered as the first
// lineage key. Implicit registration via Commit is impossible.
func (s *Store) Register(domain string, cp *Checkpoint, pub ed25519.PublicKey, keyID string) error {
	if domain == "" {
		return fmt.Errorf("anchor: empty domain_id")
	}
	if cp == nil || cp.DomainID != domain {
		return fmt.Errorf("%w: checkpoint domain mismatch", ErrMalformed)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key length %d", ErrMalformed, len(pub))
	}
	if err := cp.Verify(pub); err != nil {
		return err
	}
	return s.mutate(func() (*lineRecord, error) {
		if _, ok := s.domains[domain]; ok {
			return nil, ErrDomainRegistered
		}
		return &lineRecord{Kind: "register", Domain: domain, CP: cp,
			PubKey: hex.EncodeToString(pub), KeyID: keyID}, nil
	})
}

// Commit applies the frozen compare-and-store semantics:
//
//	seq < stored            → ErrRegression
//	seq == stored, same     → idempotent success (retry-safe)
//	seq == stored, differ   → ErrEquivocation (never accepted)
//	seq > stored            → verify lineage → persist → fsync → ack
func (s *Store) Commit(domain string, cp *Checkpoint) error {
	if cp == nil || cp.DomainID != domain {
		return fmt.Errorf("%w: checkpoint domain mismatch", ErrMalformed)
	}
	return s.mutate(func() (*lineRecord, error) {
		d := s.domains[domain]
		if d == nil {
			return nil, ErrDomainUnregistered
		}
		cur := d.Checkpoint
		switch {
		case cp.Seq < cur.Seq:
			return nil, fmt.Errorf("%w: seq %d < %d", ErrRegression, cp.Seq, cur.Seq)
		case cp.Seq == cur.Seq:
			if cp.Same(cur) {
				return nil, nil // idempotent retry — no write needed
			}
			return nil, fmt.Errorf("%w: seq %d tip %s vs stored %s",
				ErrEquivocation, cp.Seq, cp.TipHash, cur.TipHash)
		}
		if err := verifyLineage(d, cp); err != nil {
			return nil, err
		}
		return &lineRecord{Kind: "commit", Domain: domain, CP: cp}, nil
	})
}

// Latest returns the stored checkpoint for a domain.
func (s *Store) Latest(domain string) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := syscall.Flock(int(s.f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("anchor store: lock: %w", err)
	}
	defer syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN)
	if err := s.absorb(); err != nil {
		return nil, err
	}
	d := s.domains[domain]
	if d == nil {
		return nil, ErrDomainUnregistered
	}
	cp := *d.Checkpoint
	return &cp, nil
}

// AddKey extends the domain lineage during rotation grace: introducer
// is an existing lineage pubkey that must have signed the introduction
// of the new key. Lineage only ever grows — a lineage key can only
// push forward anyway, so leaving retired keys registered adds no
// rollback surface.
func (s *Store) AddKey(domain string, newPub ed25519.PublicKey, newKeyID string, introducerSig []byte) error {
	if len(newPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key length %d", ErrMalformed, len(newPub))
	}
	return s.mutate(func() (*lineRecord, error) {
		d := s.domains[domain]
		if d == nil {
			return nil, ErrDomainUnregistered
		}
		if introducedByLineage(d, domain, newKeyID, newPub, introducerSig) {
			return &lineRecord{Kind: "key", Domain: domain,
				PubKey: hex.EncodeToString(newPub), KeyID: newKeyID,
				IntroducerSig: hex.EncodeToString(introducerSig)}, nil
		}
		return nil, fmt.Errorf("%w: no lineage key authorized this introduction", ErrBadKey)
	})
}

// KeyIntroMessage is the canonical introduction preimage an existing
// lineage key signs to authorize a new key — exported for the gateway
// side of rotation.
func KeyIntroMessage(domain, keyID string, pub ed25519.PublicKey) []byte {
	msg := lp([]byte("OVARA-ANCHOR-KEY-V1"))
	msg = append(msg, lp([]byte(domain))...)
	msg = append(msg, lp([]byte(keyID))...)
	msg = append(msg, lp(pub)...)
	return msg
}

// Reset deletes the domain's entire authoritative record — the
// authority-recovery operation. There is deliberately NO
// reset-to-arbitrary-seq primitive: recovery re-runs the init ceremony
// so the new baseline is attested, not asserted. The operator-token
// gate lives in the transport layer (main.go), not here.
func (s *Store) Reset(domain string) error {
	return s.mutate(func() (*lineRecord, error) {
		if s.domains[domain] == nil {
			return nil, ErrDomainUnregistered
		}
		return &lineRecord{Kind: "reset", Domain: domain}, nil
	})
}

// Close releases the store file.
func (s *Store) Close() error { return s.f.Close() }

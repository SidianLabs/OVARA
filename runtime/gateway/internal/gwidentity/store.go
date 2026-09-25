// Package gwidentity implements the P2.3.1 cryptographic gateway
// identity: an append-only JSONL registry binding gateway_id to
// registered Ed25519 keys, plus proof-of-possession authentication.
//
// Model: GATEWAY (gw_<id>, stable name — the audience value) owns
// KEY RECORDS (key_id → public key + lifecycle state). Authentication
// is "prove possession of a key registered to this gateway_id in an
// ACTIVE (or in-grace ROTATING) state" — never merely asserting the ID.
//
// Honest boundary (per ratified P2.3 design): a software key does NOT
// prevent a full-filesystem clone — the private key copies like
// enrollment.json did. This provides cryptographic proof of
// possession, lifecycle, and duplicate-ID DETECTION when both
// instances meet in one trust domain. Clone resistance in the strict
// sense needs hardware binding (TPM) — deferred.
//
// Trust domain: one filesystem — processes sharing this file via
// flock(LOCK_EX) + tail-read, the same pattern as the P2.1 replay
// journal and P2.2 identity registry. Cross-host is a different
// domain, not claimed.
//
// Persistence failures fail closed: a configured-but-unopenable or
// corrupt registry never becomes trusted. There is no silent
// in-memory fallback — NewInMemory is an explicit config choice
// (runtime-only, documented like idregistry's memory mode).
package gwidentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/anchor"
)

type KeyState string

const (
	KeyActive     KeyState = "active"     // proves possession
	KeyRotating   KeyState = "rotating"   // proves until RotatingUntil
	KeySuperseded KeyState = "superseded" // historical verify only
	KeyRevoked    KeyState = "revoked"    // dead
	KeyDestroyed  KeyState = "destroyed"  // terminal tombstone
)

// KeyRecord is one append-only registry line: a state transition for
// (gateway_id, key_id). History is never rewritten — current state is
// the fold of every record per key. Kind "key" tags the line for the
// mixed-record journal (P2.3.2); old untagged lines parse identically.
type KeyRecord struct {
	Kind          string    `json:"kind,omitempty"` // "key"; absent in pre-P2.3.2 files
	GatewayID     string    `json:"gateway_id"`
	KeyID         string    `json:"key_id"`
	PublicKey     string    `json:"public_key"` // hex ed25519 public key
	State         KeyState  `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	ActivatedAt   time.Time `json:"activated_at,omitempty"`
	RotatingUntil time.Time `json:"rotating_until,omitempty"`
	RetiredAt     time.Time `json:"retired_at,omitempty"`
	Role          string    `json:"role,omitempty"` // "approver" = approval-root key (C2-B A1)
	Generation    uint64    `json:"generation"`
	Seq           uint64    `json:"seq,omitempty"`   // P2.3.3 journal position
	Chain         string    `json:"chain,omitempty"` // P2.3.3 running hash
}

// PeerIdentity is what a successful PoP proves — public material only.
type PeerIdentity struct {
	GatewayID string
	KeyID     string
	PublicKey ed25519.PublicKey
	State     KeyState
}

// Admission lifecycle (P2.3.2). Identity ≠ admission: a grant is an
// operator-written authorization record in the same append-only
// journal, committed atomically with the key binding it admits.
// States: authorized = PENDING admission, consumed = used once,
// denied = REJECTED. Gateway ACTIVE remains the key-record lifecycle;
// destroyed = RETIRED (terminal, per P2.3.1 semantics).
const (
	GrantAuthorized = "authorized"
	GrantConsumed   = "consumed"
	GrantDenied     = "denied"
)

// GrantRecord is an enrollment authorization line ("kind":"grant").
// An optional pinned PublicKey binds the grant to one specific key;
// empty means any presented key may consume it. Single-use: Admit
// appends a consumed transition atomically with the new key record.
type GrantRecord struct {
	Kind       string    `json:"kind"` // "grant"
	GrantID    string    `json:"grant_id"`
	GatewayID  string    `json:"gateway_id"`
	PublicKey  string    `json:"public_key,omitempty"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	ConsumedAt time.Time `json:"consumed_at,omitempty"`
	Seq        uint64    `json:"seq,omitempty"`   // P2.3.3 journal position
	Chain      string    `json:"chain,omitempty"` // P2.3.3 running hash
}

// RevokeRecord is a "revoke" journal line (P2.3.4) — a durable,
// operator-written revocation event in the domain authority journal.
// Class is one of revocation.Class{Issuer,Delegation,Lease}; Target
// is the canonical identifier for that class (issuer id, presentation
// key sha256(lp(issuer)‖lp(nonce)), or lease id). Revocation is
// append-only and permanent: there is no un-revoke record — undoing
// a kill requires new authority, not resurrection of the old.
type RevokeRecord struct {
	Kind      string    `json:"kind"`   // "revoke"
	Class     string    `json:"class"`  // issuer | delegation | lease
	Target    string    `json:"target"` // canonical id for the class
	Actor     string    `json:"actor"`  // operator identity that authorized it
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
	Seq       uint64    `json:"seq,omitempty"`   // journal position = revocation epoch
	Chain     string    `json:"chain,omitempty"` // running hash
}

var (
	ErrUnknownGateway   = errors.New("gwidentity: unknown gateway")
	ErrUnknownKey       = errors.New("gwidentity: unknown key")
	ErrGatewayConflict  = errors.New("gwidentity: gateway_id registered to a different key")
	ErrKeyNotActive     = errors.New("gwidentity: key cannot authenticate as active")
	ErrInvalidSignature = errors.New("gwidentity: invalid proof-of-possession signature")
	ErrGatewayDestroyed = errors.New("gwidentity: gateway is destroyed")
	ErrUnauthorized     = errors.New("gwidentity: no authorized enrollment grant")
	ErrUnknownGrant     = errors.New("gwidentity: unknown enrollment grant")
)

// Registry is the domain gateway-key registry. One file = one trust
// domain. All mutations: mutex → flock → absorb tail → validate →
// append → fsync → update index.
type Registry struct {
	mu          sync.Mutex
	f           *os.File // nil = in-memory mode (runtime-only, documented)
	off         int64
	keys        map[string]map[string]*KeyRecord   // gateway_id → key_id → record
	grants      map[string]*GrantRecord            // grant_id → record
	grantsByGW  map[string]map[string]*GrantRecord // gateway_id → grant_id → record
	revoked     map[string]map[string]bool         // class → target → revoked (P2.3.4)
	revokedList []*RevokeRecord                    // folded revoke records, journal order
	tips        map[string]map[string]Tip          // gateway_id → store → latest committed tip (P2.4 tip-ledger)

	// P2.3.3 chain state — folded from the journal, committed only
	// after fsync (see sealRecord/mutate).
	seq       uint64
	chain     [32]byte
	firstLine []byte // journal line 1 — domain_id preimage
	migrated  int    // "migrate" markers seen (anchor-init evidence)
	anchor    anchor.Pusher
	signer    CheckpointSigner

	// approverPin (hex) is the operator-held approver root — set via
	// SetApproverPin. Approver-role records fold only against it.
	approverPin string
}

func NewInMemory() *Registry {
	return &Registry{keys: map[string]map[string]*KeyRecord{},
		grants: map[string]*GrantRecord{}, grantsByGW: map[string]map[string]*GrantRecord{},
		revoked: map[string]map[string]bool{}, tips: map[string]map[string]Tip{}}
}

// Open loads or creates the registry file. Corrupt non-tail records
// fail — the registry cannot prove trust state it cannot read.
func Open(path string) (*Registry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("gateway registry: mkdir: %w", err)
	}
	return open(path, true)
}

// OpenExisting opens the registry but never creates it — read-side
// tooling (list/deny/retire) must not mint an empty authority store
// as a side effect of inspecting a missing path.
func OpenExisting(path string) (*Registry, error) {
	return open(path, false)
}

// open is the shared open path. New files are created 0600. An
// EXISTING file must already be owner-only: any group/other bit means
// users outside the intended trust owner can append forged authority
// records — the registry IS the enrollment authority, so its file
// permissions ARE the admission boundary. Fail closed, never chmod.
func open(path string, create bool) (*Registry, error) {
	flags := os.O_RDWR | os.O_APPEND
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("gateway registry: open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("gateway registry: stat: %w", err)
	}
	if st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("gateway registry: %s has unsafe permissions %o — must be owner-only (0600)", path, st.Mode().Perm())
	}
	r := &Registry{f: f, keys: map[string]map[string]*KeyRecord{},
		grants: map[string]*GrantRecord{}, grantsByGW: map[string]map[string]*GrantRecord{},
		revoked: map[string]map[string]bool{}, tips: map[string]map[string]Tip{}}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("gateway registry: lock: %w", err)
	}
	err = r.absorb()
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// absorb folds journal bytes appended since r.off into the index.
// Caller holds flock (or is at open). A torn final line (crash between
// write and fsync) is truncated — it was never a committed record.
// Corruption anywhere else fails the load.
func (r *Registry) absorb() error {
	st, err := r.f.Stat()
	if err != nil {
		return fmt.Errorf("gateway registry: stat: %w", err)
	}
	if st.Size() < r.off {
		// The file lost records this process already committed — history
		// was rewritten (external truncate/rollback). A smaller registry
		// must never silently become authoritative: revocation and
		// tombstone records could be rolled back. Fail closed; anchored
		// rollback detection remains deferred (P2.3 D-17).
		return fmt.Errorf("gateway registry: file shrank below committed offset %d (size %d) — history rewritten", r.off, st.Size())
	}
	if st.Size() == r.off {
		return nil
	}
	buf := make([]byte, st.Size()-r.off)
	if _, err := r.f.ReadAt(buf, r.off); err != nil {
		return fmt.Errorf("gateway registry: read: %w", err)
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
		var probe seqChainProbe
		if err := json.Unmarshal(line, &probe); err != nil {
			if nl == int64(len(buf)) {
				if err := r.f.Truncate(r.off + pos); err != nil {
					return fmt.Errorf("gateway registry: truncate torn tail: %w", err)
				}
				r.off += pos
				return nil
			}
			return fmt.Errorf("gateway registry: corrupt record at offset %d: %w", r.off+pos, err)
		}
		if err := r.chainFoldLine(line, &probe); err != nil {
			return fmt.Errorf("gateway registry: %v (offset %d)", err, r.off+pos)
		}
		switch probe.Kind {
		case "grant":
			var g GrantRecord
			if err := json.Unmarshal(line, &g); err != nil || g.GrantID == "" || g.GatewayID == "" {
				return fmt.Errorf("gateway registry: corrupt grant record at offset %d", r.off+pos)
			}
			if err := r.indexGrant(&g); err != nil {
				return err
			}
		case "", "key":
			var rec KeyRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return fmt.Errorf("gateway registry: corrupt record at offset %d: %w", r.off+pos, err)
			}
			if rec.GatewayID == "" || rec.KeyID == "" {
				return fmt.Errorf("gateway registry: record missing gateway_id/key_id at offset %d", r.off+pos)
			}
			m := r.keys[rec.GatewayID]
			if m == nil {
				m = map[string]*KeyRecord{}
				r.keys[rec.GatewayID] = m
			}
			if err := r.validateApproverLocked(&rec); err != nil {
				return err
			}
			cp := rec
			m[rec.KeyID] = &cp
		case "migrate":
			r.migrated++
		case "revoke":
			var rv RevokeRecord
			if err := json.Unmarshal(line, &rv); err != nil ||
				rv.Class == "" || rv.Target == "" {
				return fmt.Errorf("gateway registry: corrupt revoke record at offset %d", r.off+pos)
			}
			r.indexRevoke(&rv)
		case "tips":
			var tp TipsRecord
			if err := json.Unmarshal(line, &tp); err != nil || tp.GatewayID == "" {
				return fmt.Errorf("gateway registry: corrupt tips record at offset %d", r.off+pos)
			}
			r.indexTips(&tp)
		default:
			return fmt.Errorf("gateway registry: unknown record kind %q at offset %d", probe.Kind, r.off+pos)
		}
		pos = nl + 1
	}
	r.off += int64(len(buf))
	return nil
}

// indexGrant folds a grant record into both grant indexes. A grant_id
// names exactly ONE definition (gateway_id + pinned key): subsequent
// records for that id may only be state transitions. A record that
// redefines the tuple — same id, different gateway or different pin —
// is a conflicting duplicate (journal injection or operator error)
// and is refused. Identical records fold idempotently.
func (r *Registry) indexGrant(g *GrantRecord) error {
	if ex := r.grants[g.GrantID]; ex != nil &&
		(ex.GatewayID != g.GatewayID || ex.PublicKey != g.PublicKey) {
		return fmt.Errorf("gateway registry: conflicting grant definition %s (%s→%s)", g.GrantID, ex.GatewayID, g.GatewayID)
	}
	cp := *g
	r.grants[g.GrantID] = &cp
	m := r.grantsByGW[g.GatewayID]
	if m == nil {
		m = map[string]*GrantRecord{}
		r.grantsByGW[g.GatewayID] = m
	}
	m[g.GrantID] = &cp
	return nil
}

// mutate serializes a registry mutation across processes: absorb the
// tail, apply fn to the live index, append the produced records, fsync.
// A failed append never takes effect — fn runs on the fresh index but
// the caller sees the error and the file may hold a partial tail that
// the next absorb truncates. fn returns the records to commit; mixing
// *KeyRecord and *GrantRecord in one call commits them atomically —
// that is what makes grant-consumption + key-binding a single act.
func (r *Registry) mutate(fn func() ([]any, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		if err := syscall.Flock(int(r.f.Fd()), syscall.LOCK_EX); err != nil {
			return fmt.Errorf("gateway registry: lock: %w", err)
		}
		defer syscall.Flock(int(r.f.Fd()), syscall.LOCK_UN)
		if err := r.absorb(); err != nil {
			return err
		}
	}
	out, err := fn()
	if err != nil {
		return err
	}
	// Stage chain values locally — commit to r.seq/r.chain/firstLine
	// only after the records are durable, so a failed write never
	// advances in-memory chain state.
	seq, chain := r.seq, r.chain
	var newFirst []byte
	if r.f != nil {
		for _, rec := range out {
			seq++
			if chain, err = sealRecord(rec, seq, chain); err != nil {
				return err
			}
			data, err := json.Marshal(rec)
			if err != nil {
				return fmt.Errorf("gateway registry: marshal: %w", err)
			}
			data = append(data, '\n')
			if _, err := r.f.Write(data); err != nil {
				return fmt.Errorf("gateway registry: append: %w", err)
			}
			if seq == 1 {
				newFirst = append([]byte(nil), data[:len(data)-1]...)
			}
			r.off += int64(len(data))
		}
		if err := r.f.Sync(); err != nil {
			return fmt.Errorf("gateway registry: fsync: %w", err)
		}
	}
	for _, rec := range out {
		switch v := rec.(type) {
		case *KeyRecord:
			m := r.keys[v.GatewayID]
			if m == nil {
				m = map[string]*KeyRecord{}
				r.keys[v.GatewayID] = m
			}
			cp := *v
			m[v.KeyID] = &cp
		case *GrantRecord:
			if err := r.indexGrant(v); err != nil {
				return err
			}
		case *MarkerRecord:
			r.migrated++
		case *RevokeRecord:
			r.indexRevoke(v)
		case *TipsRecord:
			r.indexTips(v)
		}
	}
	if r.f != nil {
		r.seq, r.chain = seq, chain
		if newFirst != nil {
			r.firstLine = newFirst
		}
	}
	// Anchor the new tip. Ordering is the frozen invariant: local
	// mutation → fsync → checkpoint → oracle commit → caller sees
	// result. A push failure leaves the local state durable but
	// UNANCHORED (returned error, unanchored tail) — never silently
	// discarded, never silently pushed later; boot reconcile plus
	// operator catch-up is the recovery path.
	if r.anchor != nil && len(out) > 0 {
		cp, err := r.signer(seq, chain)
		if err != nil {
			return fmt.Errorf("gateway registry: anchor sign: %w", err)
		}
		if err := r.anchor.Commit(context.Background(), r.DomainID(), cp); err != nil {
			return fmt.Errorf("gateway registry: anchor commit (local state durable, unanchored): %w", err)
		}
	}
	return nil
}

// CheckpointSigner produces a signed checkpoint for (seq, tip) —
// the signer resolves its own key_id lazily (admission-time pushes
// run before the caller sees the new record).
type CheckpointSigner func(seq uint64, tip [32]byte) (*anchor.Checkpoint, error)

// SetAnchor hooks the monotonic oracle into the mutation path. Must
// be called before concurrent use. In-memory registries cannot anchor
// — a runtime-only authority store has no history to protect.
func (r *Registry) SetAnchor(p anchor.Pusher, s CheckpointSigner) error {
	if r.f == nil {
		return fmt.Errorf("gateway registry: in-memory registry cannot be anchored")
	}
	if p == nil || s == nil {
		return fmt.Errorf("gateway registry: anchor pusher and signer are both required")
	}
	r.anchor, r.signer = p, s
	return nil
}

// ReconcileResult is the verdict of local-vs-oracle comparison.
type ReconcileResult int

const (
	ReconcileOK           ReconcileResult = iota // L==A, tip matches
	ReconcileLocalBehind                         // L<A — local journal rolled back
	ReconcileEquivocation                        // L==A, tip differs — corruption or fork
	ReconcileLocalAhead                          // L>A — unanchored tail (crash window or forged tail — indistinguishable)
	ReconcileEmpty                               // local journal empty — nothing to reconcile
)

// ReconcileAnchor runs the frozen reconciliation: local chain tip vs
// the oracle's stored checkpoint. Transport/pin/signature failures of
// the oracle call return as err (fail-closed inputs); the verdict
// describes state comparison only. L>A is NEVER auto-resolved —
// pushing a local-ahead journal could crown a forged tail.
func (r *Registry) ReconcileAnchor(ctx context.Context, q anchor.Querier) (ReconcileResult, *anchor.Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		if err := syscall.Flock(int(r.f.Fd()), syscall.LOCK_EX); err != nil {
			return 0, nil, fmt.Errorf("gateway registry: lock: %w", err)
		}
		defer syscall.Flock(int(r.f.Fd()), syscall.LOCK_UN)
		if err := r.absorb(); err != nil {
			return 0, nil, err
		}
	}
	dom, seq, tip := r.ChainTip()
	if dom == "" {
		return ReconcileEmpty, nil, nil
	}
	a, err := q.Latest(ctx, dom)
	if err != nil {
		return 0, nil, err
	}
	tipHex := hex.EncodeToString(tip[:])
	switch {
	case seq < a.Seq:
		return ReconcileLocalBehind, a, nil
	case seq == a.Seq && tipHex == a.TipHash:
		return ReconcileOK, a, nil
	case seq == a.Seq:
		return ReconcileEquivocation, a, nil
	default:
		return ReconcileLocalAhead, a, nil
	}
}

// AppendMarker writes the "migrate" evidence record — the anchor-init
// ceremony's journal-side artifact. Goes through mutate, so the marker
// is chained like any other record and covered by the genesis
// checkpoint that follows it. A random note makes each ceremony's
// evidence distinct (two inits of the same base history differ).
func (r *Registry) AppendMarker() error {
	var nonce [8]byte
	rand.Read(nonce[:])
	return r.mutate(func() ([]any, error) {
		return []any{&MarkerRecord{Kind: "migrate", Note: hex.EncodeToString(nonce[:])}}, nil
	})
}

// Migrated reports how many migrate markers the journal holds —
// anchor-init refuses when >0 (already anchored → fail closed).
func (r *Registry) Migrated() int { return r.migrated }

func newKeyID() string {
	var b [12]byte
	rand.Read(b[:])
	return "gwk_" + hex.EncodeToString(b[:])
}

// Register binds (gateway_id, pubkey) on first contact. Idempotent for
// an identical rejoin (restart). CONFLICT when the gateway_id already
// holds a different key — this is the clone/squat detector: a second
// instance claiming an existing ID with a different key refuses to
// register, regardless of the old key's state (tombstones included;
// the recovery path is Rotate, never re-register).
func (r *Registry) Register(gatewayID string, pub ed25519.PublicKey) (*KeyRecord, error) {
	if gatewayID == "" {
		return nil, fmt.Errorf("gateway registry: empty gateway_id")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway registry: bad public key length %d", len(pub))
	}
	var rec *KeyRecord
	err := r.mutate(func() ([]any, error) {
		now := time.Now().UTC()
		existing := r.keys[gatewayID]
		pubHex := hex.EncodeToString(pub)
		for _, k := range existing {
			if k.PublicKey == pubHex && k.State != KeyDestroyed {
				cp := *k
				rec = &cp
				return nil, nil // idempotent rejoin
			}
		}
		if len(existing) > 0 {
			return nil, fmt.Errorf("%w (registration refused)", ErrGatewayConflict)
		}
		nr := &KeyRecord{Kind: "key", GatewayID: gatewayID, KeyID: newKeyID(),
			PublicKey: pubHex, State: KeyActive, CreatedAt: now,
			ActivatedAt: now, Generation: 1}
		rec = nr
		return []any{nr}, nil
	})
	return rec, err
}

// Rotate installs newPub as the ACTIVE key: existing ACTIVE keys enter
// ROTATING for grace (hard cut when grace<=0), ROTATING keys keep
// their own deadline, dead keys are untouched. Rotate is the recovery
// path — allowed even when every existing key is revoked — but never
// on a destroyed gateway. newPub must not already be registered for
// this gateway (a rotating/revoked record is not re-activated here).
func (r *Registry) Rotate(gatewayID string, newPub ed25519.PublicKey, grace time.Duration) (*KeyRecord, error) {
	if len(newPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway registry: bad public key length %d", len(newPub))
	}
	var rec *KeyRecord
	err := r.mutate(func() ([]any, error) {
		now := time.Now().UTC()
		existing := r.keys[gatewayID]
		if len(existing) == 0 {
			return nil, fmt.Errorf("%w — register first", ErrUnknownGateway)
		}
		pubHex := hex.EncodeToString(newPub)
		allDestroyed := true
		for _, k := range existing {
			if k.State != KeyDestroyed {
				allDestroyed = false
			}
			if k.PublicKey == pubHex {
				return nil, fmt.Errorf("key already registered for %s (state %s)", gatewayID, k.State)
			}
		}
		if allDestroyed {
			return nil, ErrGatewayDestroyed
		}
		gen := uint64(0)
		var out []any
		for _, k := range existing {
			if k.Generation > gen {
				gen = k.Generation
			}
			if k.State == KeyActive {
				rot := *k
				rot.State = KeyRotating
				rot.RotatingUntil = now.Add(grace)
				out = append(out, &rot)
			}
		}
		nr := &KeyRecord{Kind: "key", GatewayID: gatewayID, KeyID: newKeyID(),
			PublicKey: pubHex, State: KeyActive, CreatedAt: now,
			ActivatedAt: now, Generation: gen + 1}
		rec = nr
		return append(out, nr), nil
	})
	return rec, err
}

// RevokeKey kills one key. Revocation beats rotation grace — a revoked
// key never authenticates regardless of RotatingUntil.
func (r *Registry) RevokeKey(gatewayID, keyID string) error {
	return r.mutate(func() ([]any, error) {
		k, ok := r.keys[gatewayID][keyID]
		if !ok {
			return nil, fmt.Errorf("%w: %s/%s", ErrUnknownKey, gatewayID, keyID)
		}
		if k.State == KeyDestroyed {
			return nil, fmt.Errorf("%w: %s/%s tombstone is terminal", ErrGatewayDestroyed, gatewayID, keyID)
		}
		rev := *k
		rev.State = KeyRevoked
		rev.RetiredAt = time.Now().UTC()
		return []any{&rev}, nil
	})
}

// Destroy tombstones the gateway: every key → DESTROYED, terminal.
// Future Register conflicts and Rotate refuses — the ID is dead.
func (r *Registry) Destroy(gatewayID string) error {
	return r.mutate(func() ([]any, error) {
		existing := r.keys[gatewayID]
		if len(existing) == 0 {
			return nil, ErrUnknownGateway
		}
		now := time.Now().UTC()
		var out []any
		for _, k := range existing {
			if k.State == KeyDestroyed {
				continue
			}
			d := *k
			d.State = KeyDestroyed
			d.RetiredAt = now
			out = append(out, &d)
		}
		return out, nil
	})
}

// effective reports the time-adjusted state — a ROTATING key past its
// deadline reads as superseded (pure read; the stored record catches
// up on the next mutation).
func effective(k *KeyRecord, now time.Time) KeyState {
	if k.State == KeyRotating && !now.Before(k.RotatingUntil) {
		return KeySuperseded
	}
	return k.State
}

// usable reports whether the key may prove possession NOW.
func usable(k *KeyRecord, now time.Time) bool {
	switch effective(k, now) {
	case KeyActive, KeyRotating:
		return true
	}
	return false
}

// Lookup returns the gateway's records (newest last per key is the
// index state; callers get a copy). Refreshes the tail first so a
// second process's committed transition is never missed.
func (r *Registry) Lookup(gatewayID string) ([]*KeyRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		if err := syscall.Flock(int(r.f.Fd()), syscall.LOCK_EX); err != nil {
			return nil, fmt.Errorf("gateway registry: lock: %w", err)
		}
		defer syscall.Flock(int(r.f.Fd()), syscall.LOCK_UN)
		if err := r.absorb(); err != nil {
			return nil, err
		}
	}
	m := r.keys[gatewayID]
	if len(m) == 0 {
		return nil, ErrUnknownGateway
	}
	out := make([]*KeyRecord, 0, len(m))
	for _, k := range m {
		cp := *k
		out = append(out, &cp)
	}
	return out, nil
}

// FindByPub returns the record for (gateway_id, pubkey) or nil —
// used by startup to decide register vs adopt vs rotate.
func (r *Registry) FindByPub(gatewayID string, pub ed25519.PublicKey) *KeyRecord {
	recs, err := r.Lookup(gatewayID)
	if err != nil {
		return nil
	}
	pubHex := hex.EncodeToString(pub)
	for _, k := range recs {
		if k.PublicKey == pubHex {
			return k
		}
	}
	return nil
}

// HasUsableKey reports whether the gateway has any key that can prove
// possession now. The last-usable-key revocation case fails here —
// a gateway with no usable key must not serve authenticated traffic.
func (r *Registry) HasUsableKey(gatewayID string) bool {
	recs, err := r.Lookup(gatewayID)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	for _, k := range recs {
		if usable(k, now) {
			return true
		}
	}
	return false
}

// AuthenticatePeer is the single authoritative gateway-authentication
// primitive (P2.3 §12): verify a proof-of-possession signature under
// the key registered to (gateway_id, key_id). Returns the proven
// PeerIdentity — public material only, never key material.
func (r *Registry) AuthenticatePeer(gatewayID, keyID string, challenge, sig []byte) (*PeerIdentity, error) {
	if len(challenge) != ChallengeLen {
		return nil, fmt.Errorf("gwidentity: malformed challenge length %d", len(challenge))
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	recs, err := r.Lookup(gatewayID)
	if err != nil {
		return nil, err
	}
	var k *KeyRecord
	for _, rec := range recs {
		if rec.KeyID == keyID {
			k = rec
			break
		}
	}
	if k == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	if !usable(k, time.Now().UTC()) {
		return nil, fmt.Errorf("%w: %s is %s", ErrKeyNotActive, keyID, effective(k, time.Now().UTC()))
	}
	pub, err := hex.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway registry: stored key %s undecodable", keyID)
	}
	if !ed25519.Verify(pub, popMessage(gatewayID, keyID, challenge), sig) {
		return nil, ErrInvalidSignature
	}
	return &PeerIdentity{GatewayID: gatewayID, KeyID: keyID,
		PublicKey: pub, State: effective(k, time.Now().UTC())}, nil
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		return r.f.Close()
	}
	return nil
}

// indexTips folds a tips record into the ledger index: latest record
// wins per (gateway_id, store). Journal order is the ordering — a
// ledger cannot un-commit an earlier floor by folding a later one.
func (r *Registry) indexTips(tp *TipsRecord) {
	m := r.tips[tp.GatewayID]
	if m == nil {
		m = map[string]Tip{}
		r.tips[tp.GatewayID] = m
	}
	for store, tip := range tp.Tips {
		if ex, ok := m[store]; !ok || tip.Seq > ex.Seq {
			m[store] = tip
		}
	}
}

// RecordTips commits a tip-ledger record into the gateway identity
// journal — the anchored domain ledger (P2.4/C1). It rides the same
// serialized mutate path as key/revocation records, so a committed
// tips record is fsynced and, when anchoring is configured, pushed to
// the oracle in the same mutation.
//
// Ordering rule the caller must preserve: record tips ONLY after the
// covered store writes are durable (fsync returned). The ledger is a
// floor — it may lag the store, it must never claim a tip ahead of it.
func (r *Registry) RecordTips(gatewayID string, tips map[string]Tip) error {
	if len(tips) == 0 {
		return nil
	}
	rec := &TipsRecord{Kind: "tips", GatewayID: gatewayID,
		IssuedAt: time.Now().UTC(), Tips: tips}
	return r.mutate(func() ([]any, error) { return []any{rec}, nil })
}

// LatestTips returns the folded tip floor for (gateway_id) — the set
// of committed store tips the domain currently stands behind. Nil map
// when the gateway has never recorded tips.
func (r *Registry) LatestTips(gatewayID string) map[string]Tip {
	r.mu.Lock()
	defer r.mu.Unlock()
	src := r.tips[gatewayID]
	if src == nil {
		return nil
	}
	out := make(map[string]Tip, len(src))
	for s, t := range src {
		out[s] = t
	}
	return out
}

// Usable reports whether a key record may prove possession now —
// exported for the startup path's dead-key check.
func Usable(k *KeyRecord) bool { return usable(k, time.Now().UTC()) }

func newGrantID() string {
	var b [12]byte
	rand.Read(b[:])
	return "gwg_" + hex.EncodeToString(b[:])
}

// sortedGrants returns the gateway's grants in deterministic order
// (creation time, then id). Callers get copies.
func (r *Registry) sortedGrants(gatewayID string) []*GrantRecord {
	m := r.grantsByGW[gatewayID]
	gs := make([]*GrantRecord, 0, len(m))
	for _, g := range m {
		cp := *g
		gs = append(gs, &cp)
	}
	sort.Slice(gs, func(i, j int) bool {
		if !gs[i].CreatedAt.Equal(gs[j].CreatedAt) {
			return gs[i].CreatedAt.Before(gs[j].CreatedAt)
		}
		return gs[i].GrantID < gs[j].GrantID
	})
	return gs
}

// Authorize writes an enrollment grant — the operator admission path.
// pub non-nil pins the grant to exactly one key; nil admits whichever
// key the gateway proves possession of first. ttl<=0 = no expiry.
// The applicant's own boot path never calls this (see cmd/gwctl) —
// admission authority is structurally separate from the applicant.
func (r *Registry) Authorize(gatewayID string, pub ed25519.PublicKey, ttl time.Duration) (*GrantRecord, error) {
	if gatewayID == "" {
		return nil, fmt.Errorf("gateway registry: empty gateway_id")
	}
	pubHex := ""
	if pub != nil {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gateway registry: bad public key length %d", len(pub))
		}
		pubHex = hex.EncodeToString(pub)
	}
	var g *GrantRecord
	err := r.mutate(func() ([]any, error) {
		now := time.Now().UTC()
		gid := newGrantID()
		for r.grants[gid] != nil { // id must name exactly one definition
			gid = newGrantID()
		}
		ng := &GrantRecord{Kind: "grant", GrantID: gid,
			GatewayID: gatewayID, PublicKey: pubHex,
			State: GrantAuthorized, CreatedAt: now}
		if ttl != 0 {
			ng.ExpiresAt = now.Add(ttl)
		}
		g = ng
		return []any{ng}, nil
	})
	return g, err
}

// Deny rejects a pending grant — REJECTED state. A denied grant can
// never authorize admission. Denying a consumed grant is meaningless
// (the authorization was already spent) and is refused.
func (r *Registry) Deny(grantID string) error {
	return r.mutate(func() ([]any, error) {
		g := r.grants[grantID]
		if g == nil {
			return nil, fmt.Errorf("%w: %s", ErrUnknownGrant, grantID)
		}
		switch g.State {
		case GrantDenied:
			return nil, nil // idempotent
		case GrantConsumed:
			return nil, fmt.Errorf("grant %s already consumed — cannot deny", grantID)
		}
		d := *g
		d.State = GrantDenied
		return []any{&d}, nil
	})
}

// GrantsFor returns the gateway's grants (copies, deterministic order).
func (r *Registry) GrantsFor(gatewayID string) ([]*GrantRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		if err := syscall.Flock(int(r.f.Fd()), syscall.LOCK_EX); err != nil {
			return nil, fmt.Errorf("gateway registry: lock: %w", err)
		}
		defer syscall.Flock(int(r.f.Fd()), syscall.LOCK_UN)
		if err := r.absorb(); err != nil {
			return nil, err
		}
	}
	return r.sortedGrants(gatewayID), nil
}

// AllGateways returns every gateway_id with key records (sorted).
func (r *Registry) AllGateways() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.keys))
	for id := range r.keys {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Admit is the gateway's enrollment path: bind (gateway_id, pub) into
// ACTIVE only through an authorized admission. Order of decision:
//
//  1. all-destroyed → tombstone is terminal (retired gateway stays dead)
//  2. same pub already bound (non-destroyed) → idempotent adopt —
//     the binding IS the earlier admission; no re-authorization needed
//  3. other records exist → conflict (P2.3.1 rule preserved)
//  4. matching denied grant → refused (explicit deny beats everything)
//  5. authorized, unexpired, pub-matching grant → consume + register
//     atomically in one append
//  6. no grant → allowUngranted ? register : ErrUnauthorized
//
// allowUngranted is true in compat mode (gateway_require_admission
// unset) or when a TOFU pin already authorized this exact key.
func (r *Registry) Admit(gatewayID string, pub ed25519.PublicKey, allowUngranted bool) (*KeyRecord, error) {
	if gatewayID == "" {
		return nil, fmt.Errorf("gateway registry: empty gateway_id")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway registry: bad public key length %d", len(pub))
	}
	var rec *KeyRecord
	err := r.mutate(func() ([]any, error) {
		existing := r.keys[gatewayID]
		pubHex := hex.EncodeToString(pub)
		if len(existing) > 0 {
			allDestroyed := true
			for _, k := range existing {
				if k.State != KeyDestroyed {
					allDestroyed = false
				}
			}
			if allDestroyed {
				return nil, ErrGatewayDestroyed
			}
			for _, k := range existing {
				if k.PublicKey == pubHex && k.State != KeyDestroyed {
					cp := *k
					rec = &cp
					return nil, nil // idempotent adopt
				}
			}
			return nil, fmt.Errorf("%w (admission refused)", ErrGatewayConflict)
		}
		now := time.Now().UTC()
		gs := r.sortedGrants(gatewayID)
		for _, g := range gs {
			if g.State == GrantDenied && (g.PublicKey == "" || g.PublicKey == pubHex) {
				return nil, fmt.Errorf("%w: denied by grant %s", ErrUnauthorized, g.GrantID)
			}
		}
		for _, g := range gs {
			if g.State != GrantAuthorized {
				continue
			}
			if g.PublicKey != "" && g.PublicKey != pubHex {
				continue
			}
			if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
				continue
			}
			consumed := *g
			consumed.State = GrantConsumed
			consumed.ConsumedAt = now
			nr := &KeyRecord{Kind: "key", GatewayID: gatewayID,
				KeyID: newKeyID(), PublicKey: pubHex, State: KeyActive,
				CreatedAt: now, ActivatedAt: now, Generation: 1}
			rec = nr
			return []any{&consumed, nr}, nil
		}
		if !allowUngranted {
			return nil, fmt.Errorf("%w: %s", ErrUnauthorized, gatewayID)
		}
		nr := &KeyRecord{Kind: "key", GatewayID: gatewayID,
			KeyID: newKeyID(), PublicKey: pubHex, State: KeyActive,
			CreatedAt: now, ActivatedAt: now, Generation: 1}
		rec = nr
		return []any{nr}, nil
	})
	return rec, err
}

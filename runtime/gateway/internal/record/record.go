// Package record implements the OVARA 2.1 journal envelope: every
// persisted record of an authority-bearing store is a signed,
// domain-bound, hash-chained line. The signature binds
// (domain, store type, record id, seq, parent, payload, key_ref);
// the chain binds each line to the sha256 of the previous PHYSICAL
// line — reordering, insertion, deletion, duplication, forking, and
// payload mutation all fail the fold. Signature is authentication,
// not authorization: per-record legality (transitions, immutable
// cores) is enforced by each store's own fold callback.
//
// Specification: docs/OVARA_2.1_JOURNAL_SPEC.md
package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const Version = 1

// Control record types a store fold may additionally accept. Data
// records always carry the store's own type string.
const (
	TypeMigration = "migration" // first record of a migrated store
	TypeTombstone = "tombstone" // compaction marker for a terminal record
	TypeCompact   = "compact"   // signed cleanup event (replaces _cleanup)
)

// KeyRef names the signing key — resolved through the durable gateway
// identity registry so rotated keys remain verifiable.
type KeyRef struct {
	GatewayID string `json:"gateway_id"`
	KeyID     string `json:"key_id"`
}

// Link is a cross-record hash reference (evidence, never authority).
type Link struct {
	Kind string `json:"kind"`
	Hash string `json:"hash"`
}

// Envelope is one physical journal line.
type Envelope struct {
	V        int             `json:"v"`
	Type     string          `json:"type"`
	DomainID string          `json:"domain_id"`
	Seq      uint64          `json:"seq"`
	RecordID string          `json:"record_id"`
	Parent   string          `json:"parent"`
	Links    []Link          `json:"links,omitempty"`
	Payload  json.RawMessage `json:"payload"`
	KeyRef   KeyRef          `json:"key_ref"`
	Sig      string          `json:"sig"`
}

// ResolveFunc resolves a (gateway_id, key_id) pair to its registered
// public key — receipt.RegistryResolver satisfies this shape.
type ResolveFunc func(gatewayID, keyID string) (ed25519.PublicKey, error)

// Signer holds the gateway's journal signing identity.
type Signer struct {
	priv      ed25519.PrivateKey
	sign      func(payload []byte) ([]byte, error) // remote signing path
	domainID  string
	gatewayID string
	keyID     string
}

func NewSigner(priv ed25519.PrivateKey, domainID, gatewayID, keyID string) *Signer {
	if len(priv) != ed25519.PrivateKeySize || domainID == "" || gatewayID == "" || keyID == "" {
		panic("record: signer requires a full ed25519 key, domain, gateway_id and key_id")
	}
	return &Signer{priv: priv, domainID: domainID, gatewayID: gatewayID, keyID: keyID}
}

// NewRemoteSigner builds a signer whose private key lives off-box:
// each envelope payload goes to an external signing service over the
// provided callback. The gateway never possesses the approver/gateway
// private key — custody separation (C2-B A2). A failed sign call
// aborts the append (fail closed).
func NewRemoteSigner(domainID, gatewayID, keyID string, sign func(payload []byte) ([]byte, error)) *Signer {
	if sign == nil || domainID == "" || gatewayID == "" || keyID == "" {
		panic("record: remote signer requires sign func, domain, gateway_id and key_id")
	}
	return &Signer{sign: sign, domainID: domainID, gatewayID: gatewayID, keyID: keyID}
}

func (s *Signer) Domain() string { return s.domainID }
func (s *Signer) Ref() KeyRef    { return KeyRef{GatewayID: s.gatewayID, KeyID: s.keyID} }

// Sign produces a signature over an arbitrary payload through the
// signer's configured path — local key or the remote signing service
// (C2-B A2 custody model is preserved: the caller never touches the
// key). Used by artifacts that are not journal envelopes but must
// still be produced under the signing identity (e.g. lineage bundles).
func (s *Signer) Sign(payload []byte) ([]byte, error) {
	if s.sign != nil {
		return s.sign(payload)
	}
	return ed25519.Sign(s.priv, payload), nil
}

// SigningPayload is the canonical preimage an envelope signature
// covers — exported so an offline verifier can recompute it for a
// detached envelope (e.g. the approver-signed approval line carried
// inside a lineage bundle) without journal access.
func SigningPayload(env *Envelope) []byte { return signingPayload(env) }

// --- canonical signing payload (lp framing, same convention as
// identity/canon.go and receipt/edsigner.go) ---

func lp(b []byte, s string) []byte {
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(s)))
	b = append(b, lenb[:]...)
	return append(b, s...)
}

func lpb(b []byte, v []byte) []byte {
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(v)))
	b = append(b, lenb[:]...)
	return append(b, v...)
}

func lpu64(b []byte, v uint64) []byte {
	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], v)
	return append(b, vb[:]...)
}

func signingPayload(env *Envelope) []byte {
	b := []byte("OVARA-RECORD-" + env.Type + "-V1")
	b = lp(b, env.DomainID)
	b = lp(b, env.RecordID)
	b = lpu64(b, env.Seq)
	b = lp(b, env.Parent)
	b = lpb(b, env.Payload)
	b = lp(b, env.KeyRef.GatewayID)
	return lp(b, env.KeyRef.KeyID)
}

// GenesisParent is the parent hash of a store journal's first record —
// it binds the journal to (domain, store) so a journal from another
// store or domain can never graft in.
func GenesisParent(domainID, store string) string {
	sum := sha256.Sum256([]byte("OVARA-JOURNAL-GENESIS-V1" + domainID + store))
	return hex.EncodeToString(sum[:])
}

// TipHash is the hash recorded in the tip-ledger for a journal:
// sha256 of the last physical line bytes (no trailing newline).
func TipHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// Binding carries everything a store needs to open its journal in
// signed mode. Passed as a variadic option on store constructors —
// nil/absent keeps the store in legacy unsigned mode.
type Binding struct {
	Signer  *Signer
	Resolve ResolveFunc
	Floor   Floor
}

// ResumeAt creates a journal writer that continues an existing chain —
// used by compaction, which rewrites the physical file without
// resetting logical position. The file is opened for append at its
// current end: a fresh tmp path yields an empty file, while the
// post-rename reopen keeps the compacted content intact.
func ResumeAt(store, path, domainID string, signer *Signer, seq uint64, parent string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record %s: compact target: %w", store, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("record %s: compact target stat: %w", store, err)
	}
	return &Journal{store: store, domain: domainID, signer: signer, f: f,
		seq: seq, tip: parent, off: st.Size()}, nil
}

// Floor is the tip-ledger's committed watermark for one store.
// Known=false means the ledger has never recorded this store (fresh
// or unsigned-legacy — no check). A known floor requires the journal
// to contain floor.Seq with hash floor.Hash and to reach at least it.
type Floor struct {
	Known bool
	Seq   uint64
	Hash  string
}

// Journal is one open append-mode authority journal, positioned at its
// verified tip.
type Journal struct {
	store   string
	domain  string
	signer  *Signer
	resolve ResolveFunc
	f       *os.File
	seq     uint64
	tip     string
	off     int64                 // bytes folded so far (Absorb support)
	floor   Floor                 // committed floor carried for Absorb
	apply   func(*Envelope) error // fold callback retained from Open
	lastEnv *Envelope             // last appended envelope (LastEnvelope)
}

// Open loads path and folds every envelope through apply. A missing or
// empty file yields a fresh journal (tip = genesis parent). Corruption
// fails closed — no skipping, repairing, or guessing. A torn final line
// (missing newline) is truncated as an uncommitted partial write.
func Open(store, path, domainID string, signer *Signer, resolve ResolveFunc, floor Floor, apply func(*Envelope) error) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record %s: open: %w", store, err)
	}
	j := &Journal{store: store, domain: domainID, signer: signer, resolve: resolve, f: f, tip: GenesisParent(domainID, store), floor: floor, apply: apply}
	data, err := readAll(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if len(data) == 0 {
		if floor.Known {
			f.Close()
			return nil, fmt.Errorf("record %s: ledger expects tip seq %d but journal is empty — store deleted or rolled back", store, floor.Seq)
		}
		return j, nil
	}
	var seq uint64
	prev := GenesisParent(domainID, store)
	pos := 0
	for pos < len(data) {
		var firstLine bool
		if seq == 0 && pos == 0 {
			firstLine = true
		}
		nl := bytes.IndexByte(data[pos:], '\n')
		var line []byte
		end := len(data)
		if nl < 0 {
			line = data[pos:]
		} else {
			line = data[pos : pos+nl]
			end = pos + nl + 1
		}
		if len(bytes.TrimSpace(line)) == 0 {
			pos = end
			continue
		}
		var env Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			if nl < 0 {
				// torn tail: uncommitted partial write — truncate it.
				// pos stays at the torn offset so j.off tracks the
				// truncated size, not the pre-truncate read length.
				if terr := f.Truncate(int64(pos)); terr != nil {
					f.Close()
					return nil, fmt.Errorf("record %s: truncate torn tail: %w", store, terr)
				}
				break
			}
			f.Close()
			return nil, fmt.Errorf("record %s: corrupt envelope at offset %d: %w", store, pos, err)
		}
		if firstLine && env.Seq > 1 {
			// Compacted journal: continues a chain across a physical
			// rewrite. The first record MUST be a compact marker whose
			// signed payload attests the pre-compaction tip.
			if env.Type != TypeCompact {
				f.Close()
				return nil, fmt.Errorf("record %s: journal starts at seq %d without compact marker — truncated", store, env.Seq)
			}
			var cp struct {
				CompactedThrough uint64 `json:"compacted_through"`
				PriorTip         string `json:"prior_tip"`
			}
			if err := json.Unmarshal(env.Payload, &cp); err != nil ||
				cp.CompactedThrough != env.Seq-1 || cp.PriorTip != env.Parent {
				f.Close()
				return nil, fmt.Errorf("record %s: malformed compact marker at offset %d", store, pos)
			}
			seq = env.Seq - 1 // adopt attested position; chain verified below
			prev = env.Parent // the marker's signature binds this tip
			// floor inside pruned history: the compact marker is the
			// signer's attestation; a floor exactly at the boundary
			// must match its stated tip.
			if floor.Known && floor.Seq == cp.CompactedThrough && floor.Hash != cp.PriorTip {
				f.Close()
				return nil, fmt.Errorf("record %s: compact prior_tip does not match ledger floor — equivocation", store)
			}
		}
		if err := verifyEnvelope(&env, domainID, seq+1, prev, resolve); err != nil {
			f.Close()
			return nil, fmt.Errorf("record %s: %v (offset %d)", store, err, pos)
		}
		lineHash := TipHash(line)
		if floor.Known && seq+1 == floor.Seq && lineHash != floor.Hash {
			f.Close()
			return nil, fmt.Errorf("record %s: tip-ledger floor mismatch at seq %d — committed history rewritten", store, floor.Seq)
		}
		if apply != nil {
			if err := apply(&env); err != nil {
				f.Close()
				return nil, fmt.Errorf("record %s: fold error at seq %d: %w", store, seq+1, err)
			}
		}
		seq++
		prev = lineHash
		j.tip = lineHash
		pos = end
	}
	j.seq = seq
	j.off = int64(pos)
	if floor.Known && seq < floor.Seq {
		f.Close()
		return nil, fmt.Errorf("record %s: journal tip seq %d is below ledger floor %d — committed history truncated", store, seq, floor.Seq)
	}
	return j, nil
}

// Absorb folds bytes appended since the last read — multi-process
// sharing: under flock, another process may have extended the journal.
// Each new envelope must extend OUR tip (seq+1, parent=tip) — a
// cross-process fork surfaces as a parent mismatch and fails closed.
// A torn tail is truncated exactly as at open.
func (j *Journal) Absorb() error {
	st, err := j.f.Stat()
	if err != nil {
		return fmt.Errorf("record %s: absorb stat: %w", j.store, err)
	}
	if st.Size() < j.off {
		return fmt.Errorf("record %s: journal shrank — unauthorized rewrite", j.store)
	}
	if st.Size() == j.off {
		return nil
	}
	buf := make([]byte, st.Size()-j.off)
	if _, err := j.f.ReadAt(buf, j.off); err != nil {
		return fmt.Errorf("record %s: absorb read: %w", j.store, err)
	}
	pos := 0
	for pos < len(buf) {
		nl := bytes.IndexByte(buf[pos:], '\n')
		var line []byte
		end := len(buf)
		if nl < 0 {
			line = buf[pos:]
		} else {
			line = buf[pos : pos+nl]
			end = pos + nl + 1
		}
		if len(bytes.TrimSpace(line)) == 0 {
			pos = end
			continue
		}
		var env Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			if nl < 0 {
				if terr := j.f.Truncate(j.off + int64(pos)); terr != nil {
					return fmt.Errorf("record %s: truncate torn tail: %w", j.store, terr)
				}
				j.off += int64(pos)
				return nil
			}
			return fmt.Errorf("record %s: corrupt envelope at offset %d: %w", j.store, j.off+int64(pos), err)
		}
		if err := verifyEnvelope(&env, j.domain, j.seq+1, j.tip, j.resolve); err != nil {
			return fmt.Errorf("record %s: %v (offset %d)", j.store, err, j.off+int64(pos))
		}
		lineHash := TipHash(line)
		if j.floor.Known && j.seq+1 == j.floor.Seq && lineHash != j.floor.Hash {
			return fmt.Errorf("record %s: tip-ledger floor mismatch at seq %d", j.store, j.seq+1)
		}
		if j.apply != nil {
			if err := j.apply(&env); err != nil {
				return fmt.Errorf("record %s: fold error at seq %d: %w", j.store, j.seq+1, err)
			}
		}
		j.seq++
		j.tip = lineHash
		pos = end
	}
	j.off += int64(pos)
	return nil
}

func verifyEnvelope(env *Envelope, domainID string, wantSeq uint64, wantParent string, resolve ResolveFunc) error {
	if env.V != Version {
		return fmt.Errorf("unsupported envelope version %d", env.V)
	}
	if env.Seq != wantSeq {
		return fmt.Errorf("seq gap: expected %d, got %d", wantSeq, env.Seq)
	}
	if env.Parent != wantParent {
		return fmt.Errorf("parent mismatch: expected %s", wantParent)
	}
	if env.DomainID != domainID {
		return fmt.Errorf("domain mismatch: record belongs to %s", env.DomainID)
	}
	if env.RecordID == "" && env.Type != TypeMigration && env.Type != TypeCompact {
		return fmt.Errorf("record_id empty on %s record", env.Type)
	}
	pub, err := resolve(env.KeyRef.GatewayID, env.KeyRef.KeyID)
	if err != nil {
		return fmt.Errorf("key resolution failed for %s/%s: %w", env.KeyRef.GatewayID, env.KeyRef.KeyID, err)
	}
	sig, err := hex.DecodeString(env.Sig)
	if err != nil || !ed25519.Verify(pub, signingPayload(env), sig) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// Append writes one signed envelope and fsyncs. Returns the seq and
// tip hash of the committed line — callers forward these to the
// tip-ledger so the write becomes committed-floor state.
func (j *Journal) Append(typ, recordID string, payload any, links []Link) (uint64, string, error) {
	if j.signer == nil {
		return 0, "", fmt.Errorf("record %s: no signer — cannot append to signed journal", j.store)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", fmt.Errorf("record %s: marshal payload: %w", j.store, err)
	}
	env := &Envelope{
		V:        Version,
		Type:     typ,
		DomainID: j.domain,
		Seq:      j.seq + 1,
		RecordID: recordID,
		Parent:   j.tip,
		Links:    links,
		Payload:  body,
		KeyRef:   j.signer.Ref(),
	}
	var sig []byte
	if j.signer.sign != nil {
		var err error
		sig, err = j.signer.sign(signingPayload(env))
		if err != nil {
			return 0, "", fmt.Errorf("record %s: remote sign: %w", j.store, err)
		}
	} else {
		sig = ed25519.Sign(j.signer.priv, signingPayload(env))
	}
	env.Sig = hex.EncodeToString(sig)
	line, err := json.Marshal(env)
	if err != nil {
		return 0, "", fmt.Errorf("record %s: marshal envelope: %w", j.store, err)
	}
	line = append(line, '\n')
	if _, err := j.f.Write(line); err != nil {
		return 0, "", fmt.Errorf("record %s: append: %w", j.store, err)
	}
	if err := j.f.Sync(); err != nil {
		return 0, "", fmt.Errorf("record %s: fsync: %w", j.store, err)
	}
	j.seq = env.Seq
	j.tip = TipHash(line[:len(line)-1])
	j.off += int64(len(line))
	j.lastEnv = env
	return j.seq, j.tip, nil
}

// Tip returns the journal's committed tip.
func (j *Journal) Tip() (seq uint64, hash string) { return j.seq, j.tip }

// LastEnvelope returns the most recently appended envelope — the
// artifact a caller hands to another party as evidence of the write
// (its signature binds seq, parent, payload, and key_ref).
func (j *Journal) LastEnvelope() *Envelope { return j.lastEnv }

// Domain returns the journal's bound domain id.
func (j *Journal) Domain() string { return j.domain }

// Signer returns the journal's signer (for compaction rewrite).
func (j *Journal) Signer() *Signer { return j.signer }

// Store returns the journal's store name.
func (j *Journal) Store() string { return j.store }

// File returns the underlying file (callers that flock it directly).
func (j *Journal) File() *os.File { return j.f }

// Close flushes and closes the underlying file.
func (j *Journal) Close() error { return j.f.Close() }

func readAll(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("record: stat: %w", err)
	}
	buf := make([]byte, st.Size())
	if _, err := f.ReadAt(buf, 0); err != nil && st.Size() > 0 {
		return nil, fmt.Errorf("record: read: %w", err)
	}
	return buf, nil
}

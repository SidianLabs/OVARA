// Local journal hash chain (P2.3.3). Every journal line carries
// position (seq) and a running SHA-256 chain (chain). The chain's
// scoped claim — verbatim from the frozen design: it detects local
// journal modification/reordering WITHIN the local trust boundary. It
// is not, by itself, anti-rollback: an attacker who can rewrite the
// file can recompute a self-consistent chain. The independent oracle
// (monotonic seq + tip binding) is what rejects a rewritten-but-
// consistent journal; the chain is what makes the tip hash bind every
// byte of history.
//
// Chain rule per line n (seq n, 1-indexed over non-empty lines):
//
//	new-format line (seq field present):
//	    content = marshal(record with chain cleared)
//	    chain_n = sha256(chain_{n-1} || content)   — must equal embedded
//	legacy line (no seq field — pre-P2.3.3 file):
//	    chain_n = sha256(chain_{n-1} || raw line bytes)
//
// Legacy lines fold by raw bytes so migration never rewrites history;
// their order/content is still bound because raw-byte chaining is
// order-sensitive. chain_0 = 32 zero bytes.
//
// domain_id = "dom_" + hex(sha256(first journal line))[:32] — derived
// from the journal itself, never configured, so a swapped registry is
// a different domain, not a same-domain attack surface.
package gwidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// MarkerRecord is the "migrate" journal line — the migration evidence
// event anchor-init appends before registering the genesis checkpoint.
// It carries no key/grant semantics; fold verifies its chain only.
// Note is a ceremony nonce — each migration produces distinct evidence.
type MarkerRecord struct {
	Kind  string `json:"kind"` // "migrate"
	Note  string `json:"note,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	Chain string `json:"chain,omitempty"`
}

// seqChainProbe reads the chain envelope of a line without committing
// to a record type — absorb unmarshals it once and passes it here.
type seqChainProbe struct {
	Kind  string `json:"kind"`
	Seq   uint64 `json:"seq"`
	Chain string `json:"chain"`
}

// Tip is one store's committed watermark: the seq and sha256 of its
// last physical journal line at ledger-commit time (P2.4 tip-ledger).
type Tip struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// TipsRecord is a "tips" journal line (P2.4/C1): the domain tip-ledger.
// It records the committed tip of every authority-bearing store at a
// point in time inside the anchored gateway identity journal — the
// one journal whose tail an attacker cannot truncate without tripping
// the anchor. Store opens compare their folded tip against the latest
// ledger entry: a store BEHIND its floor was truncated/rolled back and
// must refuse; a store ahead is authentic-but-uncommitted and ratchets
// the floor forward at open. The ledger is evidence of expected state,
// never permission to manufacture it.
type TipsRecord struct {
	Kind      string          `json:"kind"` // "tips"
	GatewayID string          `json:"gateway_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	Tips      map[string]Tip  `json:"tips"` // store name → committed tip
	Seq       uint64          `json:"seq,omitempty"`
	Chain     string          `json:"chain,omitempty"`
}

// chainFoldLine folds one raw journal line (already parsed as p) into
// the running chain state. seq==0 → legacy line (raw bytes chain).
// seq>0 → new-format: embedded seq must equal the position and
// embedded chain must equal the recomputed value over the canonical
// (chain-cleared) marshal — anything else is modification/reordering,
// fail closed.
func (r *Registry) chainFoldLine(line []byte, p *seqChainProbe) error {
	if r.seq == 0 && r.firstLine == nil {
		r.firstLine = append([]byte(nil), line...)
	}
	wantSeq := r.seq + 1
	var content []byte
	if p.Seq == 0 {
		content = line
	} else {
		if p.Seq != wantSeq {
			return fmt.Errorf("gateway registry: chain seq break — record claims seq %d, position is %d", p.Seq, wantSeq)
		}
		if p.Chain == "" {
			return fmt.Errorf("gateway registry: record seq %d missing chain", p.Seq)
		}
		content = chainContent(line, p.Kind)
		if content == nil {
			return fmt.Errorf("gateway registry: cannot canonicalize record kind %q seq %d", p.Kind, p.Seq)
		}
		sum := sha256.Sum256(append(r.chain[:], content...))
		if hex.EncodeToString(sum[:]) != p.Chain {
			return fmt.Errorf("gateway registry: chain mismatch at seq %d — record modified or reordered", p.Seq)
		}
		r.chain = sum
		r.seq = wantSeq
		return nil
	}
	sum := sha256.Sum256(append(r.chain[:], content...))
	r.chain = sum
	r.seq = wantSeq
	return nil
}

// chainContent canonicalizes a new-format line: unmarshal to the
// concrete record, clear Chain, remarshal. Returns nil for unknown
// kinds (fold rejects separately with the proper error).
func chainContent(line []byte, kind string) []byte {
	switch kind {
	case "", "key":
		var rec KeyRecord
		if json.Unmarshal(line, &rec) != nil {
			return nil
		}
		rec.Chain = ""
		b, _ := json.Marshal(&rec)
		return b
	case "grant":
		var g GrantRecord
		if json.Unmarshal(line, &g) != nil {
			return nil
		}
		g.Chain = ""
		b, _ := json.Marshal(&g)
		return b
	case "migrate":
		var m MarkerRecord
		if json.Unmarshal(line, &m) != nil {
			return nil
		}
		m.Chain = ""
		b, _ := json.Marshal(&m)
		return b
	case "revoke":
		var rv RevokeRecord
		if json.Unmarshal(line, &rv) != nil {
			return nil
		}
		rv.Chain = ""
		b, _ := json.Marshal(&rv)
		return b
	case "tips":
		var tp TipsRecord
		if json.Unmarshal(line, &tp) != nil {
			return nil
		}
		tp.Chain = ""
		b, _ := json.Marshal(&tp)
		return b
	}
	return nil
}

// sealRecord stamps (seq, chain) onto a record about to be appended
// and returns the chain AFTER this record — pure with respect to the
// registry: mutate stages the values and commits them to r.seq/r.chain
// only after the records are durable, so a failed write never advances
// in-memory chain state.
func sealRecord(rec any, seq uint64, chain [32]byte) ([32]byte, error) {
	var content []byte
	switch v := rec.(type) {
	case *KeyRecord:
		v.Seq, v.Chain = seq, ""
		content, _ = json.Marshal(v)
	case *GrantRecord:
		v.Seq, v.Chain = seq, ""
		content, _ = json.Marshal(v)
	case *MarkerRecord:
		v.Seq, v.Chain = seq, ""
		content, _ = json.Marshal(v)
	case *RevokeRecord:
		v.Seq, v.Chain = seq, ""
		content, _ = json.Marshal(v)
	case *TipsRecord:
		v.Seq, v.Chain = seq, ""
		content, _ = json.Marshal(v)
	default:
		return chain, fmt.Errorf("gateway registry: unchainable record type %T", rec)
	}
	sum := sha256.Sum256(append(chain[:], content...))
	chainHex := hex.EncodeToString(sum[:])
	switch v := rec.(type) {
	case *KeyRecord:
		v.Chain = chainHex
	case *GrantRecord:
		v.Chain = chainHex
	case *MarkerRecord:
		v.Chain = chainHex
	case *RevokeRecord:
		v.Chain = chainHex
	case *TipsRecord:
		v.Chain = chainHex
	}
	return sum, nil
}

// DomainID derives the anchor domain from the journal's first line —
// the identity is the history, not a configured name. "" on an empty
// journal (nothing to anchor yet).
func (r *Registry) DomainID() string {
	if r.firstLine == nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("OVARA-ANCHOR-DOMAIN-V1"), r.firstLine...))
	return "dom_" + hex.EncodeToString(sum[:])[:32]
}

// ChainTip returns the journal's (domain_id, seq, tip_hash) — the
// checkpoint payload. seq==0 means an empty journal.
func (r *Registry) ChainTip() (domainID string, seq uint64, tip [32]byte) {
	return r.DomainID(), r.seq, r.chain
}

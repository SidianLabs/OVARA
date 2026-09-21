// Package anchor implements the P2.3.3 anti-rollback checkpoint
// oracle: a signed monotonic checkpoint format, a durable
// compare-and-store, and the gateway-side client.
//
// Three mechanisms, deliberately separate — none alone provides
// rollback resistance:
//
//	signature          authenticates WHO produced the checkpoint
//	oracle store       decides whether the checkpoint may move
//	                   authority forward (monotonic compare-and-store)
//	local hash chain   detects local journal modification/reorder
//	oracle pin         authenticates the intended oracle (client.go)
//
// The security property is their composition plus the oracle store's
// independent durability boundary. A checkpoint's signature does NOT
// make the journal authoritative; a stored sequence does NOT prove the
// checkpoint authentic; the pin does not authenticate the payload.
package anchor

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Checkpoint is the signed monotonic authority-history checkpoint.
// Exactly six fields — the frozen format. No timestamps (time is never
// an anti-rollback primitive), no gateway_id, no prev-ref, no
// authority state (the journal itself is the state; the tip binds it).
type Checkpoint struct {
	Version  string `json:"version"`   // "v1" — canonicalization-required
	DomainID string `json:"domain_id"` // the ONE authority domain
	Seq      uint64 `json:"seq"`       // journal sequence — the monotonic value
	TipHash  string `json:"tip_hash"`  // hex sha256 chain tip at seq
	KeyID    string `json:"key_id"`    // signer identity within the domain lineage
	Sig      string `json:"sig"`       // hex Ed25519 over Preimage()
}

const CheckpointVersion = "v1"

// lp is the canonical length-prefix encoder — u32be(len) || bytes —
// the same framing the frozen PoP canonicalization uses.
func lp(b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	return append(l[:], b...)
}

// Preimage is the ONE canonical signing representation — the same
// logical checkpoint must produce identical bytes everywhere:
//
//	lp("OVARA-ANCHOR-CP-V1") || lp(domain_id) || lp(u64be seq)
//	|| lp(tip_hash raw 32B) || lp(key_id)
//
// The signature is deliberately NOT part of the preimage.
func (c *Checkpoint) Preimage() ([]byte, error) {
	if c.Version != CheckpointVersion {
		return nil, fmt.Errorf("anchor: unsupported checkpoint version %q", c.Version)
	}
	tip, err := hex.DecodeString(c.TipHash)
	if err != nil || len(tip) != 32 {
		return nil, fmt.Errorf("anchor: tip_hash must be 32-byte hex")
	}
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], c.Seq)
	out := lp([]byte("OVARA-ANCHOR-CP-V1"))
	out = append(out, lp([]byte(c.DomainID))...)
	out = append(out, lp(sb[:])...)
	out = append(out, lp(tip)...)
	out = append(out, lp([]byte(c.KeyID))...)
	return out, nil
}

// Sign produces the checkpoint signature over the canonical preimage.
// Sig is set on the returned copy — c is not mutated.
func Sign(priv ed25519.PrivateKey, c Checkpoint) (Checkpoint, error) {
	pre, err := c.Preimage()
	if err != nil {
		return Checkpoint{}, err
	}
	c.Sig = hex.EncodeToString(ed25519.Sign(priv, pre))
	return c, nil
}

var (
	ErrBadSignature = errors.New("anchor: checkpoint signature invalid")
	ErrMalformed    = errors.New("anchor: checkpoint malformed")
)

// Verify checks the checkpoint signature under pub — authentication
// only. Whether this checkpoint may move authority is the oracle
// store's monotonic question, not the signature's.
func (c *Checkpoint) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("anchor: public key length %d", len(pub))
	}
	pre, err := c.Preimage()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: sig must be 64-byte hex", ErrMalformed)
	}
	if !ed25519.Verify(pub, pre, sig) {
		return ErrBadSignature
	}
	return nil
}

// Same reports whether two checkpoints carry identical authority state
// (everything except the signature — signature is transport, not
// state). Used for idempotent-commit equality.
func (c *Checkpoint) Same(o *Checkpoint) bool {
	return c.Version == o.Version && c.DomainID == o.DomainID &&
		c.Seq == o.Seq && c.TipHash == o.TipHash && c.KeyID == o.KeyID
}

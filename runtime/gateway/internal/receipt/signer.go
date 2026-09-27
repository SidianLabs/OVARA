package receipt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// Signer produces and verifies HMAC-SHA256 receipt signatures.
// In local mode the signing key is derived from the gateway ID. In hosted
// mode a per-tenant key should be used.
type Signer struct {
	key []byte
}

// NewSigner returns a Signer backed by the supplied secret key bytes.
// The key must be non-empty and not all-zero: such a key is public
// knowledge, so receipts signed with it are forgeable by anyone. NewSigner
// panics on an empty or all-zero key so the misconfiguration surfaces at
// construction rather than producing silently forgeable receipts.
func NewSigner(key []byte) *Signer {
	if len(key) == 0 {
		panic("receipt: NewSigner called with empty signing key")
	}
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		panic("receipt: NewSigner called with all-zero signing key")
	}
	return &Signer{key: key}
}

// Sign produces an HMAC-SHA256 signature over the receipt fields required
// by RFC 0003 and returns the signature string in "sig_v2:<hex>" format.
// (sig_v1's pipe-joined preimage was field-boundary ambiguous.)
func (s *Signer) Sign(r *models.Receipt) string {
	payload := s.canonicalPayload(r)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return "sig_v2:" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks whether the stored signature on r matches a freshly
// computed HMAC-SHA256 over the receipt's RFC 0003 canonical fields.
func (s *Signer) Verify(r *models.Receipt) bool {
	if r == nil {
		return false
	}
	expected := s.Sign(r)
	return hmac.Equal([]byte(expected), []byte(r.Signature))
}

// signatureVersion extracts "sig_v2" or "" from a signature string so
// callers can distinguish future signing schemes.
func signatureVersion(sig string) string {
	if idx := strings.IndexByte(sig, ':'); idx > 0 {
		return sig[:idx]
	}
	return ""
}

// canonicalPayload builds the deterministic byte sequence that is signed.
// The fields and ordering match the ExecutionReceipt primitive defined in
// the RFC. Every field is lp-framed (u32be length + bytes, same convention
// as identity/canon.go) so adjacent string fields can never smear across
// a boundary — the earlier pipe-joined form hashed "a|b"+"c" identically
// to "a"+"b|c".
func (s *Signer) canonicalPayload(r *models.Receipt) []byte {
	b := lp([]byte("OVARA-RECEIPT-HMAC-V2"))
	b = append(b, lp([]byte(r.ReceiptID))...)
	b = append(b, lp([]byte(r.DecisionID))...)
	b = append(b, lp([]byte(r.ActionDigest))...)
	b = append(b, lp([]byte(r.ActionType))...)
	b = append(b, lp([]byte(r.Resource))...)
	b = append(b, lp([]byte(r.AgentID))...)
	b = append(b, lp([]byte(r.Decision))...)
	b = append(b, lp([]byte(r.PolicyVersion))...)
	var f [8]byte
	binary.BigEndian.PutUint64(f[:], math.Float64bits(r.TrustScore))
	b = append(b, lp(f[:])...)
	var tb [8]byte
	// #nosec G115 -- int64->u64 is injective; a preimage only needs a
	// bijection, not sortable order.
	binary.BigEndian.PutUint64(tb[:], uint64(r.IssuedAt.Unix()))
	return append(b, lp(tb[:])...)
}

// ComputeActionDigest returns a hex-encoded SHA-256 digest of the canonical
// representation of an action request. This digest is placed in ReceiptStub
// before the receipt is built and signed. Same lp framing — the earlier
// "%s|%s|%d" form was field-boundary ambiguous.
func ComputeActionDigest(actionType, resource string, issuedAt time.Time) string {
	b := lp([]byte("OVARA-ACTION-DIGEST-V2"))
	b = append(b, lp([]byte(actionType))...)
	b = append(b, lp([]byte(resource))...)
	var tb [8]byte
	// #nosec G115 -- int64->u64 is injective for a preimage encoding.
	binary.BigEndian.PutUint64(tb[:], uint64(issuedAt.Unix()))
	h := sha256.Sum256(append(b, lp(tb[:])...))
	return hex.EncodeToString(h[:])
}

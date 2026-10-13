package receipt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// HMACPrefix tags the gateway's HMAC receipt signature. It was "sig_v1:",
// the same prefix the proxy's Ed25519 receipt chain uses; a tool reading
// both could take one for the other. The HMAC is a symmetric check only
// the gateway itself can make, not a signature anyone can verify: the
// gateway's Ed25519 gateway_sig is what /v1/receipts/verify checks.
const HMACPrefix = "hmac_v1:"

// Sign produces an HMAC-SHA256 over the receipt fields required by RFC
// 0003 and returns it as "hmac_v1:<hex>".
func (s *Signer) Sign(r *models.Receipt) string {
	payload := s.canonicalPayload(r)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return HMACPrefix + hex.EncodeToString(mac.Sum(nil))
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

// signatureVersion extracts "hmac_v1" or "" from a signature string so
// callers can distinguish future signing schemes.
func signatureVersion(sig string) string {
	if idx := strings.IndexByte(sig, ':'); idx > 0 {
		return sig[:idx]
	}
	return ""
}

// canonicalPayload builds the deterministic byte sequence that is signed.
// The fields and ordering match the ExecutionReceipt primitive defined in
// the RFC and are stable across releases.
func (s *Signer) canonicalPayload(r *models.Receipt) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%f|%d",
		r.ReceiptID,
		r.DecisionID,
		r.ActionDigest,
		r.ActionType,
		r.Resource,
		r.AgentID,
		r.Decision,
		r.PolicyVersion,
		r.TrustScore,
		r.IssuedAt.Unix(),
	)
}

// ComputeActionDigest returns a hex-encoded SHA-256 digest of the canonical
// representation of an action request. This digest is placed in ReceiptStub
// before the receipt is built and signed.
func ComputeActionDigest(actionType, resource string, issuedAt time.Time) string {
	payload := fmt.Sprintf("%s|%s|%d", actionType, resource, issuedAt.Unix())
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

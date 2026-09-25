package receipt

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
)

// ReceiptDomain separates receipt signatures from every other
// artifact the gateway key signs (PoP challenges, anchor
// checkpoints). A signature under a different domain can never be
// replayed as a receipt signature.
const ReceiptDomain = "OVARA-RECEIPT-SIG-V1"

// sigPrefix tags Ed25519 receipt signatures so they are
// distinguishable from the HMAC sig_v1 scheme.
const sigPrefix = "edsig_v1:"

var (
	// ErrNoRegistry means verification was attempted without an
	// authoritative key source. Never silently trusted.
	ErrNoRegistry = errors.New("receipt: no gateway key registry — cannot verify")
	// ErrUnsigned marks a receipt that carries no gateway signature.
	ErrUnsigned = errors.New("receipt: no gateway_sig present")
)

// EdSigner stamps and signs receipts with the gateway's Ed25519
// private key (P2.3.1). The private key never leaves the signer —
// only the signature and the (gateway_id, key_id) resolution hints
// appear on the receipt.
type EdSigner struct {
	priv      ed25519.PrivateKey
	gatewayID string
	keyID     string
}

// NewEdSigner binds the gateway's signing identity. gatewayID and
// keyID must be the durably-registered record for priv — the server
// wires them from the authenticated registry record at startup, after
// admission, so a receipt can never claim a key binding the registry
// does not already know.
func NewEdSigner(priv ed25519.PrivateKey, gatewayID, keyID string) *EdSigner {
	if len(priv) != ed25519.PrivateKeySize || gatewayID == "" || keyID == "" {
		panic("receipt: NewEdSigner requires a full ed25519 key and registered gateway_id/key_id")
	}
	return &EdSigner{priv: priv, gatewayID: gatewayID, keyID: keyID}
}

// SignReceipt stamps (gateway_id, gateway_key_id) onto r and signs
// the canonical receipt payload. The stamped identity fields are
// themselves covered by the signature — substituting them invalidates
// it.
func (s *EdSigner) SignReceipt(r *models.Receipt) {
	r.GatewayID = s.gatewayID
	r.GatewayKeyID = s.keyID
	r.GatewaySig = sigPrefix + hex.EncodeToString(
		ed25519.Sign(s.priv, SignedPayload(r)))
}

// lp is the wire length-prefix — u32be(len) ‖ bytes — the same
// framing the identity and PoP canonical builders use.
func lp(b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	return append(l[:], b...)
}

// SignedPayload builds the deterministic preimage the gateway signs.
// Every Receipt field is covered except GatewaySig itself (the HMAC
// Signature field IS covered — callers sign after the HMAC exists).
// Fixed order, lp-framed, domain-separated — no ambiguity, no
// collision with PoP or delegation payloads.
func SignedPayload(r *models.Receipt) []byte {
	out := lp([]byte(ReceiptDomain))
	out = append(out, lp([]byte(r.ReceiptID))...)
	out = append(out, lp([]byte(r.DecisionID))...)
	out = append(out, lp([]byte(r.ActionDigest))...)
	out = append(out, lp([]byte(r.ActionType))...)
	out = append(out, lp([]byte(r.Resource))...)
	out = append(out, lp([]byte(r.AgentID))...)
	out = append(out, lp([]byte(r.CapabilityLeaseID))...)
	out = append(out, lp([]byte(r.Decision))...)
	out = append(out, lp([]byte(r.PolicyVersion))...)
	out = append(out, lp([]byte(strconv.FormatFloat(r.TrustScore, 'f', 6, 64)))...)
	out = append(out, lp([]byte(r.TrustLevel))...)
	// Anomaly signals: fixed per-item framing inside one lp field,
	// stored order is the canonical order.
	var anom []byte
	for _, a := range r.AnomalySignals {
		anom = append(anom, lp([]byte(a.Code))...)
		anom = append(anom, lp([]byte(a.Pattern))...)
		anom = append(anom, lp([]byte(a.Severity))...)
	}
	out = append(out, lp(anom)...)
	out = append(out, lp([]byte(btoi(r.ShieldActive)))...)
	out = append(out, lp([]byte(btoi(r.Restricted)))...)
	out = append(out, lp([]byte(strconv.Itoa(r.RiskCount)))...)
	out = append(out, lp([]byte(r.ApprovalID))...)
	out = append(out, lp([]byte(r.ApprovalDecision))...)
	out = append(out, lp([]byte(strconv.FormatUint(r.TrustEpoch, 10)))...)
	out = append(out, lp([]byte(strconv.FormatInt(r.IssuedAt.UnixNano(), 10)))...)
	out = append(out, lp([]byte(r.GatewayID))...)
	out = append(out, lp([]byte(r.GatewayKeyID))...)
	// The HMAC field is covered too: buildReceipt computes it before
	// signing, and binding it means stripping/forging the sig_v1 field
	// invalidates the whole signed receipt — not just the HMAC check.
	out = append(out, lp([]byte(r.Signature))...)
	return out
}

func btoi(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// KeyResolver resolves the AUTHORITATIVE historical public key for
// (gateway_id, key_id). Implementations read the gateway identity
// registry — a key in ANY recorded state (active, superseded,
// revoked, destroyed) resolves: historical verification is distinct
// from live authentication. Unknown pairs return an error.
type KeyResolver interface {
	ResolvePublicKey(gatewayID, keyID string) (ed25519.PublicKey, error)
}

// RegistryResolver resolves keys through the durable gwidentity
// registry — the same authority journal that records key lifecycle.
type RegistryResolver struct {
	Reg *gwidentity.Registry
}

// ResolvePublicKey returns the registered public key regardless of
// lifecycle state — superseded and revoked keys still verify the
// receipts they signed while trusted. It deliberately does NOT apply
// Usable(): that is the live-authentication check, not the
// historical-verification check.
func (rr RegistryResolver) ResolvePublicKey(gatewayID, keyID string) (ed25519.PublicKey, error) {
	if rr.Reg == nil {
		return nil, ErrNoRegistry
	}
	recs, err := rr.Reg.Lookup(gatewayID)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		if rec.KeyID != keyID || rec.Role == "approver" {
			// C2-B A1: approver-root keys resolve ONLY through the
			// approvals journal (Registry.ResolveApproverKey) — a
			// gateway-key resolver must never bless them, or the two
			// signing domains collapse into one.
			continue
		}
		pub, err := hex.DecodeString(rec.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("receipt: stored key %s undecodable", keyID)
		}
		return ed25519.PublicKey(pub), nil
	}
	return nil, fmt.Errorf("receipt: %w for %s", gwidentity.ErrUnknownKey, keyID)
}

// VerifySignature is the single authoritative receipt-signature
// check: parse → resolve the historical key via the registry →
// reconstruct the canonical payload → ed25519.Verify. A public key
// carried inside the receipt is NEVER trusted — the receipt only
// names which registry record to use. Returns (valid, error):
// resolution/encoding failures are errors (unverifiable, not false),
// cryptographic mismatch is (false, nil).
func VerifySignature(res KeyResolver, r *models.Receipt) (bool, error) {
	if r == nil {
		return false, errors.New("receipt: nil")
	}
	if !strings.HasPrefix(r.GatewaySig, sigPrefix) {
		return false, ErrUnsigned
	}
	sig, err := hex.DecodeString(r.GatewaySig[len(sigPrefix):])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, nil // malformed/truncated signature ≠ valid
	}
	if res == nil {
		return false, ErrNoRegistry
	}
	pub, err := res.ResolvePublicKey(r.GatewayID, r.GatewayKeyID)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, SignedPayload(r), sig), nil
}

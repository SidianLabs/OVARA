package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"ovara.services.receipt/internal/models"
)

// signaturePrefix matches the "sig_v1:" scheme produced by the gateway's
// receipt signer (runtime/gateway/internal/receipt/signer.go).
const signaturePrefix = "sig_v1:"

// canonicalPayload builds the deterministic byte sequence that is verified.
// The field order matches the gateway signer
// (runtime/gateway/internal/receipt/signer.go):
// ReceiptID|DecisionID|ActionDigest|ActionType|Resource|AgentID|Decision|PolicyVersion|TrustScore|IssuedAt
// so signatures produced by the gateway verify byte-exact here. The stored
// receipt ID serves as the gateway's ReceiptID.
func canonicalPayload(r *models.Receipt) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%f|%d",
		r.ID, r.DecisionID, r.ActionDigest,
		r.ActionType, r.Resource, r.AgentID,
		r.Decision, r.PolicyVersion,
		r.TrustScore, r.IssuedAt.Unix(),
	)
}

// signReceipt computes "sig_v1:<hex(HMAC-SHA256)>" over the canonical payload.
func signReceipt(key []byte, r *models.Receipt) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonicalPayload(r)))
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// verifySignature checks the stored signature against a freshly computed
// HMAC. Both the "sig_v1:<hex>" form and a bare hex HMAC are accepted.
func verifySignature(key []byte, r *models.Receipt) bool {
	if len(key) == 0 || r == nil || r.Signature == "" {
		return false
	}
	expected := signReceipt(key, r)
	if hmac.Equal([]byte(expected), []byte(r.Signature)) {
		return true
	}
	return hmac.Equal(
		[]byte(strings.TrimPrefix(expected, signaturePrefix)),
		[]byte(r.Signature),
	)
}

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
//
// ASSUMPTION: the gateway signer signs fields this service does not store
// (ActionDigest, PolicyVersion), so byte-exact RFC 0003 verification is not
// possible here. We verify an HMAC-SHA256 over the documented canonical
// format using the fields this service persists — the same field order used
// by (*models.Receipt).Digest. Deployments needing byte-exact gateway
// verification must extend the stored schema to include the missing fields.
func canonicalPayload(r *models.Receipt) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%d",
		r.ID, r.DecisionID, r.GatewayID, r.OrganizationID,
		r.ActionType, r.Resource, r.Decision, r.AgentID,
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

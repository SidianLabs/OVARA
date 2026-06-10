package receipt

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type CrossOrgReceipt struct {
	ReceiptID      string    `json:"receipt_id"`
	DecisionID     string    `json:"decision_id"`
	IssuingGateway string    `json:"issuing_gateway"`
	IssuingOrg     string    `json:"issuing_org"`
	ActionType     string    `json:"action_type"`
	Resource       string    `json:"resource"`
	Decision       string    `json:"decision"`
	AgentIdentity  string    `json:"agent_identity"`
	LeaseDigest    string    `json:"lease_digest,omitempty"`
	TrustScore     float64   `json:"trust_score"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      []byte    `json:"signature"`
}

func (r *CrossOrgReceipt) Verify(publicKey []byte) bool {
	if len(r.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	payload := r.Digest()
	return ed25519.Verify(publicKey, []byte(payload), r.Signature)
}

func (r *CrossOrgReceipt) Digest() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%d",
		r.ReceiptID, r.DecisionID, r.IssuingGateway, r.IssuingOrg,
		r.ActionType, r.Resource, r.Decision, r.AgentIdentity,
		r.TrustScore, r.Timestamp.Unix(),
	)
	return payload
}

func SignCrossOrgReceipt(receipt *CrossOrgReceipt, signingKey ed25519.PrivateKey) error {
	payload := receipt.Digest()
	sig := ed25519.Sign(signingKey, []byte(payload))
	receipt.Signature = sig
	return nil
}

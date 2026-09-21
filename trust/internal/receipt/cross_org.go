package receipt

import (
	"crypto/ed25519"
	"encoding/json"
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
	return ed25519.Verify(publicKey, r.Digest(), r.Signature)
}

// Digest returns the canonical (JSON) byte representation of the fields
// covered by the receipt signature. TrustScore is serialized losslessly.
func (r *CrossOrgReceipt) Digest() []byte {
	payload, _ := json.Marshal(struct {
		ReceiptID      string  `json:"receipt_id"`
		DecisionID     string  `json:"decision_id"`
		IssuingGateway string  `json:"issuing_gateway"`
		IssuingOrg     string  `json:"issuing_org"`
		ActionType     string  `json:"action_type"`
		Resource       string  `json:"resource"`
		Decision       string  `json:"decision"`
		AgentIdentity  string  `json:"agent_identity"`
		LeaseDigest    string  `json:"lease_digest"`
		TrustScore     float64 `json:"trust_score"`
		Timestamp      int64   `json:"timestamp"`
	}{
		ReceiptID:      r.ReceiptID,
		DecisionID:     r.DecisionID,
		IssuingGateway: r.IssuingGateway,
		IssuingOrg:     r.IssuingOrg,
		ActionType:     r.ActionType,
		Resource:       r.Resource,
		Decision:       r.Decision,
		AgentIdentity:  r.AgentIdentity,
		LeaseDigest:    r.LeaseDigest,
		TrustScore:     r.TrustScore,
		Timestamp:      r.Timestamp.Unix(),
	})
	return payload
}

func SignCrossOrgReceipt(receipt *CrossOrgReceipt, signingKey ed25519.PrivateKey) error {
	receipt.Signature = ed25519.Sign(signingKey, receipt.Digest())
	return nil
}

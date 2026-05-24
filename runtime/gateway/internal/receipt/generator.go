package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

type Receipt struct {
	ReceiptID        string    `json:"receipt_id"`
	ActionDigest     string    `json:"action_digest"`
	ActionType       string    `json:"action_type"`
	Resource         string    `json:"resource"`
	AgentIDRef       string    `json:"agent_id,omitempty"`
	CapabilityLeaseID string   `json:"capability_lease_id,omitempty"`
	DelegationChainHash string `json:"delegation_chain_hash,omitempty"`
	Decision         string    `json:"decision"`
	PolicyVersion    string    `json:"policy_version"`
	TrustContextSummary *TrustSummary `json:"trust_context,omitempty"`
	ApprovalRef      string    `json:"approval_ref,omitempty"`
	IssuedAt         time.Time `json:"issued_at"`
	Signature        string    `json:"signature"`
}

type TrustSummary struct {
	Score        float64 `json:"score"`
	Environment  string  `json:"environment"`
}

func (g *Generator) GenerateFromStub(stub *models.ReceiptStub, agentID, capLeaseID string) *Receipt {
	return &Receipt{
		ReceiptID:         stub.ReceiptID,
		ActionDigest:      stub.ActionDigest,
		ActionType:        stub.ActionType,
		Resource:          stub.Resource,
		AgentIDRef:        agentID,
		CapabilityLeaseID: capLeaseID,
		Decision:          stub.ActionType,
		PolicyVersion:     stub.PolicyVersion,
		TrustContextSummary: &TrustSummary{
			Score:       stub.TrustContextScore,
			Environment: "",
		},
		IssuedAt:  stub.IssuedAt,
		Signature: g.sign(stub),
	}
}

func (g *Generator) sign(stub *models.ReceiptStub) string {
	h := sha256.New()
	h.Write([]byte(stub.ReceiptID))
	h.Write([]byte(stub.ActionDigest))
	h.Write([]byte(stub.ActionType))
	h.Write([]byte(stub.Resource))
	h.Write([]byte(stub.PolicyVersion))
	return "sig_v1_local:" + hex.EncodeToString(h.Sum(nil))[:16]
}
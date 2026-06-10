package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Receipt struct {
	ID            string    `json:"id"`
	DecisionID    string    `json:"decision_id"`
	GatewayID     string    `json:"gateway_id"`
	OrganizationID string   `json:"organization_id"`
	ActionType    string    `json:"action_type"`
	Resource      string    `json:"resource"`
	Decision      string    `json:"decision"`
	AgentID       string    `json:"agent_id,omitempty"`
	TrustScore    float64   `json:"trust_score"`
	Payload       string    `json:"payload"`
	Signature     string    `json:"signature"`
	IssuedAt      time.Time `json:"issued_at"`
	ArchivedAt    time.Time `json:"archived_at"`
}

func (r *Receipt) Digest() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%d",
		r.ID, r.DecisionID, r.GatewayID, r.OrganizationID,
		r.ActionType, r.Resource, r.Decision, r.AgentID,
		r.TrustScore, r.IssuedAt.Unix(),
	)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

type VerificationResult struct {
	Valid         bool     `json:"valid"`
	ReceiptDigest string   `json:"receipt_digest"`
	Errors        []string `json:"errors,omitempty"`
}

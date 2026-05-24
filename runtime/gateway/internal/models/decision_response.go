package models

import "time"

type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionDeny     Decision = "deny"
	DecisionEscalate  Decision = "escalate"
)

type ReasonCode string

const (
	ReasonAllowed          ReasonCode = "allowed"
	ReasonDenied           ReasonCode = "denied"
	ReasonEscalate         ReasonCode = "escalate"
	ReasonCapabilityExpiry ReasonCode = "capability_expired"
	ReasonActionNotAllowed ReasonCode = "action_not_allowed"
	ReasonResourceNotCovered ReasonCode = "resource_not_covered"
	ReasonMissingIdentity  ReasonCode = "missing_identity"
	ReasonProductionDenied ReasonCode = "production_denied"
)

type DecisionResponse struct {
	DecisionID       string       `json:"decision_id"`
	Decision         Decision     `json:"decision"`
	ReasonCodes      []ReasonCode `json:"reason_codes"`
	TrustScore       float64      `json:"trust_score,omitempty"`
	RequiresApproval bool         `json:"requires_approval"`
	ReceiptStub      *ReceiptStub `json:"receipt_stub,omitempty"`
}

type ReceiptStub struct {
	ReceiptID        string    `json:"receipt_id"`
	ActionDigest      string    `json:"action_digest"`
	ActionType        string    `json:"action_type"`
	Resource          string    `json:"resource"`
	PolicyVersion     string    `json:"policy_version"`
	TrustContextScore float64   `json:"trust_context_score,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
}
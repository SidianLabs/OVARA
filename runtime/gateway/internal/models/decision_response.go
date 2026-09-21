package models

import "time"

type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionDeny     Decision = "deny"
	DecisionEscalate Decision = "escalate"
)

type ReasonCode string

const (
	ReasonAllowed              ReasonCode = "allowed"
	ReasonPolicyAllow          ReasonCode = "policy_allow"
	ReasonPolicyDeny           ReasonCode = "policy_deny"
	ReasonPolicyEscalate       ReasonCode = "policy_escalate"
	ReasonTrustEscalate        ReasonCode = "trust_escalate"
	ReasonDeny                 ReasonCode = "denied"
	ReasonEscalate             ReasonCode = "escalate"
	ReasonCapabilityExpiry     ReasonCode = "capability_expired"
	ReasonCapabilityNotAllowed ReasonCode = "capability_not_allowed"
	ReasonCapabilityScope      ReasonCode = "capability_scope_mismatch"
	ReasonCapabilityRevoked    ReasonCode = "capability_revoked"
	ReasonActionNotAllowed     ReasonCode = "action_not_allowed"
	ReasonResourceNotCovered   ReasonCode = "resource_not_covered"
	ReasonMissingIdentity      ReasonCode = "missing_identity"
	ReasonIdentityInvalid      ReasonCode = "identity_invalid"
	ReasonProductionDenied     ReasonCode = "production_denied"
	ReasonTrustLow             ReasonCode = "trust_low"
	ReasonTrustMedium          ReasonCode = "trust_medium"
	ReasonAnomalyDetected      ReasonCode = "anomaly_detected"
	ReasonContainmentActive    ReasonCode = "containment_active"
	ReasonLeaseRequired        ReasonCode = "lease_required"
	ReasonDelegationScope      ReasonCode = "delegation_scope_mismatch"
	ReasonRepeatedRisk         ReasonCode = "repeated_risk"
	ReasonRiskyShellPattern    ReasonCode = "risky_shell_pattern"
	ReasonRiskyGitPattern      ReasonCode = "risky_git_pattern"
	ReasonProductionTarget     ReasonCode = "production_target"
	ReasonWeakLeaseScope       ReasonCode = "weak_lease_scope"
	// P2.3.4 revocation boundary outcomes — distinct from capability
	// revocation so operators can tell "killed" from "unprovable".
	ReasonRevoked               ReasonCode = "revoked"
	ReasonRevocationUnavailable ReasonCode = "revocation_unavailable"
	ReasonRevocationEpoch       ReasonCode = "revocation_epoch_stale"
)

type DecisionResponse struct {
	DecisionID        string        `json:"decision_id"`
	Decision          Decision      `json:"decision"`
	ReasonCodes       []ReasonCode  `json:"reason_codes"`
	TrustScore        float64       `json:"trust_score,omitempty"`
	TrustLevel        TrustLevel    `json:"trust_level,omitempty"`
	RequiresApproval  bool          `json:"requires_approval"`
	ApprovalID        string        `json:"approval_id,omitempty"`
	ReceiptStub       *ReceiptStub  `json:"receipt_stub,omitempty"`
	TrustContext      *TrustContext `json:"trust_context,omitempty"`
	EvaluationSummary string        `json:"evaluation_summary,omitempty"`
}

type TrustLevel string

const (
	TrustLevelHigh   TrustLevel = "high"
	TrustLevelMedium TrustLevel = "medium"
	TrustLevelLow    TrustLevel = "low"
	TrustLevelNone   TrustLevel = "none"
)

type TrustContext struct {
	Score          float64         `json:"score"`
	Level          TrustLevel      `json:"level"`
	AnomalySignals []AnomalySignal `json:"anomaly_signals,omitempty"`
	ShieldActive   bool            `json:"shield_active,omitempty"`
	Restricted     bool            `json:"restricted,omitempty"`
	RiskCount      int             `json:"risk_count,omitempty"`
	EvaluationTime time.Time       `json:"evaluation_time"`
}

type AnomalySignal struct {
	Code     string `json:"code"`
	Pattern  string `json:"pattern,omitempty"`
	Severity string `json:"severity"`
}

type ReceiptStub struct {
	ReceiptID         string  `json:"receipt_id"`
	ActionDigest      string  `json:"action_digest"`
	ActionType        string  `json:"action_type"`
	Resource          string  `json:"resource"`
	PolicyVersion     string  `json:"policy_version"`
	TrustContextScore float64 `json:"trust_context_score,omitempty"`
	// TrustEpoch is the domain revocation epoch the decision was made
	// against (P2.3.4) — the receipt binds the authority view, so a
	// later revocation never rewrites what was decided under it.
	TrustEpoch uint64    `json:"trust_epoch,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
}

type Receipt struct {
	ReceiptID         string          `json:"receipt_id"`
	DecisionID        string          `json:"decision_id"`
	ActionDigest      string          `json:"action_digest"`
	ActionType        string          `json:"action_type"`
	Resource          string          `json:"resource"`
	AgentID           string          `json:"agent_id,omitempty"`
	CapabilityLeaseID string          `json:"capability_lease_id,omitempty"`
	Decision          string          `json:"decision"`
	PolicyVersion     string          `json:"policy_version"`
	TrustScore        float64         `json:"trust_score"`
	TrustLevel        TrustLevel      `json:"trust_level,omitempty"`
	AnomalySignals    []AnomalySignal `json:"anomaly_signals,omitempty"`
	ShieldActive      bool            `json:"shield_active,omitempty"`
	Restricted        bool            `json:"restricted,omitempty"`
	RiskCount         int             `json:"risk_count,omitempty"`
	ApprovalID        string          `json:"approval_id,omitempty"`
	ApprovalDecision  string          `json:"approval_decision,omitempty"`
	// TrustEpoch is the revocation epoch the decision was made against
	// (P2.3.4). Informational — outside the HMAC preimage so adding it
	// never invalidates already-signed receipts. Bound into GatewaySig
	// (P2.3.5): the signature attests WHICH authority view produced it.
	TrustEpoch uint64 `json:"trust_epoch,omitempty"`
	// P2.3.5 asymmetric receipt signature — authenticity/integrity of
	// the signed receipt under the identified gateway key, verifiable
	// by anyone holding the authoritative registry. GatewayID/KeyID are
	// key-RESOLUTION hints only; the verifier resolves the public key
	// from the gateway identity registry, never from the receipt. All
	// three fields are covered by the Ed25519 signature itself.
	GatewayID    string    `json:"gateway_id,omitempty"`
	GatewayKeyID string    `json:"gateway_key_id,omitempty"`
	GatewaySig   string    `json:"gateway_sig,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	Signature    string    `json:"signature"`
}

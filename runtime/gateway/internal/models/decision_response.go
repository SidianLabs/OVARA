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
	ReasonAllowed               ReasonCode = "allowed"
	ReasonDenied                ReasonCode = "denied"
	ReasonEscalate              ReasonCode = "escalate"
	ReasonCapabilityExpiry      ReasonCode = "capability_expired"
	ReasonCapabilityNotAllowed  ReasonCode = "capability_not_allowed"
	ReasonCapabilityScope       ReasonCode = "capability_scope_mismatch"
	ReasonActionNotAllowed      ReasonCode = "action_not_allowed"
	ReasonResourceNotCovered    ReasonCode = "resource_not_covered"
	ReasonMissingIdentity       ReasonCode = "missing_identity"
	ReasonIdentityInvalid      ReasonCode = "identity_invalid"
	ReasonProductionDenied      ReasonCode = "production_denied"
	ReasonTrustLow              ReasonCode = "trust_low"
	ReasonTrustMedium          ReasonCode = "trust_medium"
	ReasonAnomalyDetected      ReasonCode = "anomaly_detected"
	ReasonContainmentActive    ReasonCode = "containment_active"
	ReasonRepeatedRisk         ReasonCode = "repeated_risk"
	ReasonRiskyShellPattern    ReasonCode = "risky_shell_pattern"
	ReasonRiskyGitPattern      ReasonCode = "risky_git_pattern"
	ReasonProductionTarget      ReasonCode = "production_target"
	ReasonWeakLeaseScope        ReasonCode = "weak_lease_scope"
)

type DecisionResponse struct {
	DecisionID       string       `json:"decision_id"`
	Decision         Decision     `json:"decision"`
	ReasonCodes      []ReasonCode `json:"reason_codes"`
	TrustScore       float64      `json:"trust_score,omitempty"`
	TrustLevel       TrustLevel   `json:"trust_level,omitempty"`
	RequiresApproval bool         `json:"requires_approval"`
	ApprovalID       string       `json:"approval_id,omitempty"`
	ReceiptStub      *ReceiptStub `json:"receipt_stub,omitempty"`
	TrustContext     *TrustContext `json:"trust_context,omitempty"`
}

type TrustLevel string

const (
	TrustLevelHigh   TrustLevel = "high"
	TrustLevelMedium TrustLevel = "medium"
	TrustLevelLow    TrustLevel = "low"
	TrustLevelNone   TrustLevel = "none"
)

type TrustContext struct {
	Score         float64         `json:"score"`
	Level         TrustLevel      `json:"level"`
	AnomalySignals []AnomalySignal `json:"anomaly_signals,omitempty"`
	ShieldActive  bool            `json:"shield_active,omitempty"`
	Restricted    bool            `json:"restricted,omitempty"`
	RiskCount     int             `json:"risk_count,omitempty"`
	EvaluationTime time.Time      `json:"evaluation_time"`
}

type AnomalySignal struct {
	Code    string `json:"code"`
	Pattern string `json:"pattern,omitempty"`
	Severity string `json:"severity"`
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

type Receipt struct {
	ReceiptID          string    `json:"receipt_id"`
	DecisionID         string    `json:"decision_id"`
	ActionDigest       string    `json:"action_digest"`
	ActionType         string    `json:"action_type"`
	Resource           string    `json:"resource"`
	AgentID            string    `json:"agent_id,omitempty"`
	CapabilityLeaseID  string    `json:"capability_lease_id,omitempty"`
	Decision           string    `json:"decision"`
	PolicyVersion      string    `json:"policy_version"`
	TrustScore         float64   `json:"trust_score"`
	ApprovalID         string    `json:"approval_id,omitempty"`
	ApprovalDecision   string    `json:"approval_decision,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
	Signature          string    `json:"signature"`
}
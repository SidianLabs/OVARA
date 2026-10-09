package approval

import (
	"encoding/json"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

type ApprovalRequest struct {
	ApprovalID   string             `json:"approval_id"`
	DecisionID   string             `json:"decision_id"`
	ActionType   models.ActionType  `json:"action_type"`
	Resource     string             `json:"resource"`
	Environment  models.Environment `json:"environment"`
	Status       Status             `json:"status"`
	CreatedAt    time.Time          `json:"created_at"`
	ResolvedAt   *time.Time         `json:"resolved_at,omitempty"`
	ResumedAt    *time.Time         `json:"resumed_at,omitempty"`
	ResolvedBy   string             `json:"resolved_by,omitempty"`
	AgentID      string             `json:"agent_id,omitempty"`
	Reason       string             `json:"reason,omitempty"`
	TrustScore   float64            `json:"trust_score,omitempty"`
	TrustLevel   models.TrustLevel  `json:"trust_level,omitempty"`
	AnomalyCodes []string           `json:"anomaly_codes,omitempty"`
	ShieldActive bool               `json:"shield_active,omitempty"`
	Restricted   bool               `json:"restricted,omitempty"`
	// Context is what the approver should SEE about the request beyond its
	// URL: the query string, body size and type, a short redacted body
	// preview. It is copied from the metadata of the request the gateway
	// evaluated (never from the approval caller) and is display-only: it
	// grants nothing and is not used for any authorization decision.
	Context map[string]string `json:"context,omitempty"`
	// RequestHash binds this approval to the exact evaluated request
	// (sha256 over action/resource/agent/lease). Empty for legacy records.
	RequestHash   string `json:"request_hash,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	// P2.3.4 — the revocation identifiers of the authority this approval
	// was created under, captured from the evaluated request. Claim-time
	// revalidation of the continuation checks them against CURRENT
	// revocation state; the approval record itself stays historical.
	LeaseID       string   `json:"lease_id,omitempty"`
	DelegationKeys []string `json:"delegation_keys,omitempty"`
	Issuers       []string `json:"issuers,omitempty"`
}

func (a *ApprovalRequest) MarshalJSON() ([]byte, error) {
	type Alias ApprovalRequest
	return json.Marshal(&struct {
		*Alias
		Status string `json:"status"`
	}{
		Alias:  (*Alias)(a),
		Status: string(a.Status),
	})
}

func (a *ApprovalRequest) Approve(resolvedBy string) {
	a.Status = StatusApproved
	a.ResolvedBy = resolvedBy
	now := time.Now().UTC()
	a.ResolvedAt = &now
}

func (a *ApprovalRequest) Deny(resolvedBy, reason string) {
	a.Status = StatusDenied
	a.ResolvedBy = resolvedBy
	a.Reason = reason
	now := time.Now().UTC()
	a.ResolvedAt = &now
}

// MarkResumed consumes the single-use resume token for an approved
// approval. Called by the store while holding its lock.
func (a *ApprovalRequest) MarkResumed() {
	now := time.Now().UTC()
	a.ResumedAt = &now
}

// CanResume reports whether a resume may still be performed: the approval
// must be approved and its resume token must not have been consumed.
func (a *ApprovalRequest) CanResume() bool {
	return a.Status == StatusApproved && a.ResumedAt == nil
}

func (a *ApprovalRequest) IsPending() bool {
	return a.Status == StatusPending
}

func (a *ApprovalRequest) IsResolved() bool {
	return a.Status == StatusApproved || a.Status == StatusDenied
}

type CreateRequest struct {
	DecisionID    string             `json:"decision_id"`
	ActionType    models.ActionType  `json:"action_type"`
	Resource      string             `json:"resource"`
	Environment   models.Environment `json:"environment"`
	AgentID       string             `json:"agent_id,omitempty"`
	TrustScore    float64            `json:"trust_score,omitempty"`
	TrustLevel    models.TrustLevel  `json:"trust_level,omitempty"`
	AnomalyCodes  []string           `json:"anomaly_codes,omitempty"`
	ShieldActive  bool               `json:"shield_active,omitempty"`
	Restricted    bool               `json:"restricted,omitempty"`
	// Context is filled in by the gateway from the evaluated request, never
	// from the caller (json:"-").
	Context       map[string]string  `json:"-"`
	RequestHash   string             `json:"request_hash,omitempty"`
	PolicyVersion string             `json:"policy_version,omitempty"`
	// P2.3.4 authority identifiers — server-populated from the recorded
	// decision request, never caller-authoritative.
	LeaseID       string   `json:"lease_id,omitempty"`
	DelegationKeys []string `json:"delegation_keys,omitempty"`
	Issuers       []string `json:"issuers,omitempty"`
}

func (c *CreateRequest) ToApproval(approvalID string) *ApprovalRequest {
	return &ApprovalRequest{
		ApprovalID:    approvalID,
		DecisionID:    c.DecisionID,
		ActionType:    c.ActionType,
		Resource:      c.Resource,
		Environment:   c.Environment,
		Status:        StatusPending,
		CreatedAt:     time.Now().UTC(),
		AgentID:       c.AgentID,
		TrustScore:    c.TrustScore,
		TrustLevel:    c.TrustLevel,
		AnomalyCodes:  c.AnomalyCodes,
		ShieldActive:  c.ShieldActive,
		Restricted:    c.Restricted,
		Context:       c.Context,
		RequestHash:   c.RequestHash,
		PolicyVersion: c.PolicyVersion,
		LeaseID:       c.LeaseID,
		DelegationKeys: c.DelegationKeys,
		Issuers:       c.Issuers,
	}
}

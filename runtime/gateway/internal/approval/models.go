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
	ApprovalID  string    `json:"approval_id"`
	DecisionID  string    `json:"decision_id"`
	ActionType  models.ActionType `json:"action_type"`
	Resource    string    `json:"resource"`
	Environment models.Environment `json:"environment"`
	Status      Status    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy  string    `json:"resolved_by,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

func (a *ApprovalRequest) MarshalJSON() ([]byte, error) {
	type Alias ApprovalRequest
	return json.Marshal(&struct {
		*Alias
		Status string `json:"status"`
	}{
		Alias:   (*Alias)(a),
		Status:  string(a.Status),
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

func (a *ApprovalRequest) IsPending() bool {
	return a.Status == StatusPending
}

func (a *ApprovalRequest) IsResolved() bool {
	return a.Status == StatusApproved || a.Status == StatusDenied
}

type CreateRequest struct {
	DecisionID  string            `json:"decision_id"`
	ActionType  models.ActionType `json:"action_type"`
	Resource    string            `json:"resource"`
	Environment models.Environment `json:"environment"`
	AgentID     string            `json:"agent_id,omitempty"`
}

func (c *CreateRequest) ToApproval(approvalID string) *ApprovalRequest {
	return &ApprovalRequest{
		ApprovalID:  approvalID,
		DecisionID:  c.DecisionID,
		ActionType:  c.ActionType,
		Resource:    c.Resource,
		Environment: c.Environment,
		Status:      StatusPending,
		CreatedAt:   time.Now().UTC(),
		AgentID:     c.AgentID,
	}
}
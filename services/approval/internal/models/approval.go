package models

import (
	"time"
)

type ApprovalState string

const (
	StatePending  ApprovalState = "pending"
	StateApproved ApprovalState = "approved"
	StateDenied   ApprovalState = "denied"
	StateExpired  ApprovalState = "expired"
)

type Approval struct {
	ID            string        `json:"id"`
	GatewayID     string        `json:"gateway_id"`
	DecisionID    string        `json:"decision_id"`
	ActionType    string        `json:"action_type"`
	Resource      string        `json:"resource"`
	AgentID       string        `json:"agent_id,omitempty"`
	RequestedBy   string        `json:"requested_by"`
	State         ApprovalState `json:"state"`
	Reason        string        `json:"reason,omitempty"`
	ResolvedBy    string        `json:"resolved_by,omitempty"`
	ExpiresAt     time.Time     `json:"expires_at"`
	CreatedAt     time.Time     `json:"created_at"`
	ResolvedAt    *time.Time    `json:"resolved_at,omitempty"`
}

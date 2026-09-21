package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type AlertType string

const (
	AlertTypeAnomaly          AlertType = "anomaly"
	AlertTypeTrustDegradation AlertType = "trust_degradation"
	AlertTypeContainment      AlertType = "containment"
	AlertTypePolicyViolation  AlertType = "policy_violation"
	AlertTypeCapabilityAbuse  AlertType = "capability_abuse"
)

type AlertState string

const (
	AlertStateNew           AlertState = "new"
	AlertStateAcknowledged AlertState = "acknowledged"
	AlertStateResolved     AlertState = "resolved"
)

type Alert struct {
	ID             string     `json:"id"`
	Severity       Severity   `json:"severity"`
	Type           AlertType  `json:"type"`
	AgentID        string     `json:"agent_id"`
	GatewayID      string     `json:"gateway_id"`
	OrganizationID string     `json:"organization_id"`
	Action         string     `json:"action"`
	Resource       string     `json:"resource"`
	TrustScore     float64    `json:"trust_score"`
	Message        string     `json:"message"`
	Timestamp      time.Time  `json:"timestamp"`
	State          AlertState `json:"state"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

type ConditionType string

const (
	ConditionTrustBelow          ConditionType = "trust_below"
	ConditionAnomalyCount        ConditionType = "anomaly_count"
	ConditionExcessiveEscalations ConditionType = "excessive_escalations"
	ConditionCapabilityChain     ConditionType = "capability_chain"
)

type AlertRule struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Condition     ConditionType `json:"condition"`
	Threshold     float64       `json:"threshold"`
	WindowSeconds int           `json:"window_seconds"`
	Severity      Severity      `json:"severity"`
	Enabled       bool          `json:"enabled"`
}

type AlertFilter struct {
	Severity       Severity
	Type           AlertType
	State          AlertState
	AgentID        string
	GatewayID      string
	OrganizationID string
	Limit          int
	Offset         int
}

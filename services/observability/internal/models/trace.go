package models

import "time"

type EventType string

const (
	EventActionRequested  EventType = "action_requested"
	EventPolicyEvaluated  EventType = "policy_evaluated"
	EventTrustComputed    EventType = "trust_computed"
	EventApprovalRequested EventType = "approval_requested"
	EventActionExecuted   EventType = "action_executed"
	EventReceiptIssued    EventType = "receipt_issued"
	EventAnomalyDetected  EventType = "anomaly_detected"
)

type NodeType string

const (
	NodeTypeAction    NodeType = "action"
	NodeTypePolicy    NodeType = "policy"
	NodeTypeTrust     NodeType = "trust"
	NodeTypeApproval  NodeType = "approval"
	NodeTypeExecution NodeType = "execution"
	NodeTypeReceipt   NodeType = "receipt"
)

type EdgeRelationship string

const (
	RelTriggeredBy EdgeRelationship = "triggered_by"
	RelDecidedBy   EdgeRelationship = "decided_by"
	RelApprovedBy  EdgeRelationship = "approved_by"
	RelProduced    EdgeRelationship = "produced"
)

type SpanStatus string

const (
	SpanOK    SpanStatus = "ok"
	SpanError SpanStatus = "error"
)

type TraceEvent struct {
	TraceID        string            `json:"trace_id"`
	SpanID         string            `json:"span_id"`
	ParentSpanID   string            `json:"parent_span_id,omitempty"`
	EventType      EventType         `json:"event_type"`
	AgentID        string            `json:"agent_id"`
	Action         string            `json:"action"`
	Resource       string            `json:"resource,omitempty"`
	Decision       string            `json:"decision,omitempty"`
	TrustScore     float64           `json:"trust_score,omitempty"`
	PolicyVersion  string            `json:"policy_version,omitempty"`
	GatewayID      string            `json:"gateway_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
	Duration       time.Duration     `json:"duration,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type TraceSpan struct {
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Service      string            `json:"service"`
	Operation    string            `json:"operation"`
	Start        time.Time         `json:"start"`
	End          time.Time         `json:"end"`
	Status       SpanStatus        `json:"status"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

type TraceNode struct {
	ID        string            `json:"id"`
	Type      NodeType          `json:"type"`
	Label     string            `json:"label"`
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type TraceEdge struct {
	From         string          `json:"from"`
	To           string          `json:"to"`
	Relationship EdgeRelationship `json:"relationship"`
}

type TraceGraph struct {
	Nodes []TraceNode `json:"nodes"`
	Edges []TraceEdge `json:"edges"`
}

type LineageRecord struct {
	ActionDigest string      `json:"action_digest"`
	AgentID      string      `json:"agent_id"`
	Events       []TraceEvent `json:"events"`
	Graph        TraceGraph   `json:"graph"`
}

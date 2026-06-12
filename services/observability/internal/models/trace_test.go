package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventType_Constants(t *testing.T) {
	tests := []struct {
		et       EventType
		expected string
	}{
		{EventActionRequested, "action_requested"},
		{EventPolicyEvaluated, "policy_evaluated"},
		{EventTrustComputed, "trust_computed"},
		{EventApprovalRequested, "approval_requested"},
		{EventActionExecuted, "action_executed"},
		{EventReceiptIssued, "receipt_issued"},
		{EventAnomalyDetected, "anomaly_detected"},
	}
	for _, tt := range tests {
		if string(tt.et) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.et))
		}
	}
}

func TestNodeType_Constants(t *testing.T) {
	tests := []struct {
		nt       NodeType
		expected string
	}{
		{NodeTypeAction, "action"},
		{NodeTypePolicy, "policy"},
		{NodeTypeTrust, "trust"},
		{NodeTypeApproval, "approval"},
		{NodeTypeExecution, "execution"},
		{NodeTypeReceipt, "receipt"},
	}
	for _, tt := range tests {
		if string(tt.nt) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.nt))
		}
	}
}

func TestEdgeRelationship_Constants(t *testing.T) {
	tests := []struct {
		er       EdgeRelationship
		expected string
	}{
		{RelTriggeredBy, "triggered_by"},
		{RelDecidedBy, "decided_by"},
		{RelApprovedBy, "approved_by"},
		{RelProduced, "produced"},
	}
	for _, tt := range tests {
		if string(tt.er) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.er))
		}
	}
}

func TestSpanStatus_Constants(t *testing.T) {
	if string(SpanOK) != "ok" {
		t.Errorf("expected SpanOK = ok, got %q", string(SpanOK))
	}
	if string(SpanError) != "error" {
		t.Errorf("expected SpanError = error, got %q", string(SpanError))
	}
}

func TestTraceEvent_JSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	e := TraceEvent{
		TraceID:        "trace-001",
		SpanID:         "span-001",
		ParentSpanID:   "span-000",
		EventType:      EventActionRequested,
		AgentID:        "agt-001",
		Action:         "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		TrustScore:     0.85,
		PolicyVersion:  "v1",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		Timestamp:      now,
		Duration:       5 * time.Millisecond,
		Metadata:       map[string]string{"key": "value"},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TraceEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.TraceID != e.TraceID {
		t.Errorf("expected trace_id %q, got %q", e.TraceID, decoded.TraceID)
	}
	if decoded.TrustScore != 0.85 {
		t.Errorf("expected trust_score 0.85, got %f", decoded.TrustScore)
	}
	if decoded.Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value, got %v", decoded.Metadata)
	}
}

func TestTraceEvent_OmitEmpty(t *testing.T) {
	e := TraceEvent{
		TraceID:   "trace-001",
		SpanID:    "span-001",
		EventType: EventActionRequested,
		AgentID:   "agt-001",
		Action:    "shell",
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	str := string(data)

	empty := []string{"parent_span_id", "resource", "decision", "trust_score", "policy_version", "gateway_id", "organization_id", "duration", "metadata"}
	for _, key := range empty {
		if contains(str, key) {
			t.Errorf("expected %s to be omitted", key)
		}
	}
}

func TestTraceGraph_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	g := TraceGraph{
		Nodes: []TraceNode{
			{ID: "n1", Type: NodeTypeAction, Label: "shell", Timestamp: now},
			{ID: "n2", Type: NodeTypePolicy, Label: "v1", Timestamp: now},
		},
		Edges: []TraceEdge{
			{From: "n1", To: "n2", Relationship: RelDecidedBy},
		},
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TraceGraph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(decoded.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(decoded.Nodes))
	}
	if len(decoded.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(decoded.Edges))
	}
	if decoded.Edges[0].Relationship != RelDecidedBy {
		t.Errorf("expected decided_by, got %s", decoded.Edges[0].Relationship)
	}
}

func TestLineageRecord_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	r := LineageRecord{
		ActionDigest: "sha256:abc123",
		AgentID:      "agt-001",
		Events: []TraceEvent{
			{TraceID: "t1", SpanID: "s1", EventType: EventActionRequested, AgentID: "agt-001", Action: "shell", Timestamp: now},
		},
		Graph: TraceGraph{
			Nodes: []TraceNode{{ID: "n1", Type: NodeTypeAction, Label: "shell", Timestamp: now}},
		},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded LineageRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ActionDigest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %s", decoded.ActionDigest)
	}
	if len(decoded.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(decoded.Events))
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

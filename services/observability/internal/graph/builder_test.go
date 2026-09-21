package graph

import (
	"testing"
	"time"

	"ovara.services.observability/internal/models"
)

func newTestEvents() []models.TraceEvent {
	now := time.Now().UTC()
	return []models.TraceEvent{
		{
			TraceID:   "trace-001",
			SpanID:    "span-1",
			EventType: models.EventActionRequested,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			Timestamp: now,
		},
		{
			TraceID:   "trace-001",
			SpanID:    "span-2",
			EventType: models.EventPolicyEvaluated,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			Timestamp: now.Add(time.Second),
		},
		{
			TraceID:   "trace-001",
			SpanID:    "span-3",
			EventType: models.EventTrustComputed,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			TrustScore: 0.85,
			Timestamp: now.Add(2 * time.Second),
		},
		{
			TraceID:   "trace-001",
			SpanID:    "span-4",
			EventType: models.EventApprovalRequested,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			Timestamp: now.Add(3 * time.Second),
		},
		{
			TraceID:   "trace-001",
			SpanID:    "span-5",
			EventType: models.EventActionExecuted,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			Decision:  "allow",
			Timestamp: now.Add(4 * time.Second),
		},
		{
			TraceID:   "trace-001",
			SpanID:    "span-6",
			EventType: models.EventReceiptIssued,
			AgentID:   "agt-001",
			Action:    "shell.execute",
			Timestamp: now.Add(5 * time.Second),
		},
	}
}

func TestBuildLineage(t *testing.T) {
	b := NewBuilder()
	events := newTestEvents()
	g := b.BuildLineage(events)

	if len(g.Nodes) != 6 {
		t.Errorf("expected 6 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 5 {
		t.Errorf("expected 5 edges, got %d", len(g.Edges))
	}
}

func TestBuildLineageEmpty(t *testing.T) {
	b := NewBuilder()
	g := b.BuildLineage(nil)

	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(g.Edges))
	}
}

func TestBuildAgentGraph(t *testing.T) {
	b := NewBuilder()
	events := newTestEvents()

	otherEvt := models.TraceEvent{
		TraceID:   "trace-002",
		SpanID:    "span-x",
		EventType: models.EventActionRequested,
		AgentID:   "agt-999",
		Action:    "deploy.container",
		Timestamp: time.Now().UTC(),
	}
	events = append(events, otherEvt)

	g := b.BuildAgentGraph("agt-001", events)
	if len(g.Nodes) != 6 {
		t.Errorf("expected 6 nodes for agt-001, got %d", len(g.Nodes))
	}
	for _, node := range g.Nodes {
		if node.Metadata["agent_id"] != "agt-001" {
			t.Errorf("unexpected agent_id %s in node", node.Metadata["agent_id"])
		}
	}
}

func TestDetectCycles(t *testing.T) {
	b := NewBuilder()

	graph := models.TraceGraph{
		Nodes: []models.TraceNode{
			{ID: "a", Type: models.NodeTypeAction},
			{ID: "b", Type: models.NodeTypePolicy},
			{ID: "c", Type: models.NodeTypeTrust},
		},
		Edges: []models.TraceEdge{
			{From: "a", To: "b", Relationship: models.RelTriggeredBy},
			{From: "b", To: "c", Relationship: models.RelDecidedBy},
			{From: "c", To: "a", Relationship: models.RelTriggeredBy},
		},
	}

	cycles := b.DetectCycles(graph)
	if len(cycles) == 0 {
		t.Error("expected to detect cycle")
	}
}

func TestDetectNoCycles(t *testing.T) {
	b := NewBuilder()
	events := newTestEvents()
	g := b.BuildLineage(events)

	cycles := b.DetectCycles(g)
	if len(cycles) != 0 {
		t.Errorf("expected no cycles, got %d", len(cycles))
	}
}

func TestFindCriticalPath(t *testing.T) {
	b := NewBuilder()
	events := newTestEvents()
	g := b.BuildLineage(events)

	path := b.FindCriticalPath(g)
	if len(path) == 0 {
		t.Error("expected non-empty critical path")
	}
}

func TestMergeGraphs(t *testing.T) {
	b := NewBuilder()

	g1 := models.TraceGraph{
		Nodes: []models.TraceNode{
			{ID: "n1", Type: models.NodeTypeAction, Timestamp: time.Now()},
			{ID: "n2", Type: models.NodeTypePolicy, Timestamp: time.Now()},
		},
		Edges: []models.TraceEdge{
			{From: "n1", To: "n2", Relationship: models.RelTriggeredBy},
		},
	}

	g2 := models.TraceGraph{
		Nodes: []models.TraceNode{
			{ID: "n2", Type: models.NodeTypePolicy, Timestamp: time.Now()},
			{ID: "n3", Type: models.NodeTypeTrust, Timestamp: time.Now()},
		},
		Edges: []models.TraceEdge{
			{From: "n2", To: "n3", Relationship: models.RelDecidedBy},
		},
	}

	merged := b.MergeGraphs([]models.TraceGraph{g1, g2})
	if len(merged.Nodes) != 3 {
		t.Errorf("expected 3 unique nodes, got %d", len(merged.Nodes))
	}
	if len(merged.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(merged.Edges))
	}
}

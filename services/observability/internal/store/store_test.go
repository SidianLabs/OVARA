package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.services.observability/internal/models"
)

func newTestEvent(traceID string) *models.TraceEvent {
	return &models.TraceEvent{
		TraceID:     traceID,
		SpanID:      "span-001",
		EventType:   models.EventActionRequested,
		AgentID:     "agt-001",
		Action:      "shell.execute",
		Resource:    "/bin/bash",
		Timestamp:   time.Now().UTC(),
		GatewayID:   "gw-001",
	}
}

func TestIngestAndGetTrace(t *testing.T) {
	s := NewMemoryStore(100)
	evt := newTestEvent("trace-001")

	if err := s.Ingest(evt); err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	record, err := s.GetTrace("trace-001")
	if err != nil {
		t.Fatalf("GetTrace failed: %v", err)
	}
	if record.AgentID != "agt-001" {
		t.Errorf("AgentID = %v, want agt-001", record.AgentID)
	}
	if len(record.Events) != 1 {
		t.Errorf("events = %d, want 1", len(record.Events))
	}
}

func TestIngestFull(t *testing.T) {
	s := NewMemoryStore(2)
	s.Ingest(newTestEvent("t1"))
	s.Ingest(newTestEvent("t2"))

	err := s.Ingest(newTestEvent("t3"))
	if err == nil {
		t.Error("expected store full error")
	}
}

func TestQueryByAgent(t *testing.T) {
	s := NewMemoryStore(100)

	e1 := newTestEvent("t1")
	e1.AgentID = "agt-a"
	s.Ingest(e1)

	e2 := newTestEvent("t2")
	e2.AgentID = "agt-b"
	s.Ingest(e2)

	results, _ := s.Query(TraceFilter{AgentID: "agt-a"})
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}
	if results[0].AgentID != "agt-a" {
		t.Errorf("AgentID = %v, want agt-a", results[0].AgentID)
	}
}

func TestQueryByDecision(t *testing.T) {
	s := NewMemoryStore(100)

	e1 := newTestEvent("t1")
	e1.Decision = "allow"
	s.Ingest(e1)

	e2 := newTestEvent("t2")
	e2.Decision = "deny"
	s.Ingest(e2)

	results, _ := s.Query(TraceFilter{Decision: "deny"})
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}
}

func TestQueryPagination(t *testing.T) {
	s := NewMemoryStore(100)
	for i := range 5 {
		evt := newTestEvent("trace-" + string(rune('0'+i)))
		s.Ingest(evt)
	}

	results, _ := s.Query(TraceFilter{Limit: 2})
	if len(results) != 2 {
		t.Errorf("expected 2, got %d", len(results))
	}

	results2, _ := s.Query(TraceFilter{Limit: 2, Offset: 2})
	if len(results2) != 2 {
		t.Errorf("expected 2, got %d", len(results2))
	}
}

func TestQueryEmpty(t *testing.T) {
	s := NewMemoryStore(100)
	results, err := s.Query(TraceFilter{})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if results == nil {
		t.Error("Query should return empty slice, not nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestGetTraceNotFound(t *testing.T) {
	s := NewMemoryStore(100)
	_, err := s.GetTrace("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestGetAgentLineage(t *testing.T) {
	s := NewMemoryStore(100)

	e1 := newTestEvent("t1")
	e1.AgentID = "agt-x"
	e1.EventType = models.EventActionRequested
	s.Ingest(e1)

	e2 := newTestEvent("t1")
	e2.AgentID = "agt-x"
	e2.SpanID = "span-002"
	e2.EventType = models.EventActionExecuted
	s.Ingest(e2)

	e3 := newTestEvent("t2")
	e3.AgentID = "agt-y"
	s.Ingest(e3)

	records, err := s.GetAgentLineage("agt-x", 10)
	if err != nil {
		t.Fatalf("GetAgentLineage failed: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 lineage record, got %d", len(records))
	}
	if len(records[0].Events) != 2 {
		t.Errorf("expected 2 events in lineage, got %d", len(records[0].Events))
	}
}

func TestGetAgentLineageEmpty(t *testing.T) {
	s := NewMemoryStore(100)
	records, err := s.GetAgentLineage("nonexistent", 10)
	if err != nil {
		t.Fatalf("GetAgentLineage failed: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0, got %d", len(records))
	}
}

func TestGetGraph(t *testing.T) {
	s := NewMemoryStore(100)

	e1 := newTestEvent("t1")
	e1.EventType = models.EventActionRequested
	e1.SpanID = "span-a"
	s.Ingest(e1)

	e2 := newTestEvent("t1")
	e2.EventType = models.EventPolicyEvaluated
	e2.SpanID = "span-b"
	s.Ingest(e2)

	g, err := s.GetGraph("t1")
	if err != nil {
		t.Fatalf("GetGraph failed: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(g.Edges))
	}
}

func TestGetGraphNotFound(t *testing.T) {
	s := NewMemoryStore(100)
	_, err := s.GetGraph("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestCount(t *testing.T) {
	s := NewMemoryStore(100)
	for i := range 5 {
		s.Ingest(newTestEvent("trace-" + string(rune('0'+i))))
	}
	if s.Count() != 5 {
		t.Errorf("count = %d, want 5", s.Count())
	}
}

func TestFileStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traces.jsonl")

	s1, err := NewFileStore(path, 100)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	evt := newTestEvent("file-trace-001")
	if err := s1.Ingest(evt); err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	s2, err := NewFileStore(path, 100)
	if err != nil {
		t.Fatalf("NewFileStore (reload) failed: %v", err)
	}
	if s2.Count() != 1 {
		t.Errorf("expected 1 event after reload, got %d", s2.Count())
	}

	record, err := s2.GetTrace("file-trace-001")
	if err != nil {
		t.Fatalf("GetTrace after reload failed: %v", err)
	}
	if record.AgentID != "agt-001" {
		t.Errorf("AgentID = %v, want agt-001", record.AgentID)
	}

	os.Remove(path)
}

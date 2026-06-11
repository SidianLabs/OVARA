package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.observability/internal/models"
	"ovara.services.observability/internal/store"
)

func newObsStore() store.Store {
	return store.NewMemoryStore(10000)
}

func TestObsHandle_NotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	w := httptest.NewRecorder()
	h.HandleTraces(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestIngest_ValidRequest(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	body := map[string]interface{}{
		"trace_id":   "trace-001",
		"span_id":    "span-001",
		"agent_id":   "agent-001",
		"action":     "shell",
		"event_type": "action_requested",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingest(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var evt models.TraceEvent
	json.Unmarshal(w.Body.Bytes(), &evt)
	if evt.TraceID != "trace-001" {
		t.Errorf("expected trace-001, got %s", evt.TraceID)
	}
}

func TestIngest_MissingFields(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	body := map[string]interface{}{
		"trace_id": "trace-001",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestIngest_InvalidJSON(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestIngestBatch_Valid(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	body := []map[string]interface{}{
		{
			"trace_id": "trace-001",
			"span_id":  "span-001",
			"agent_id": "agent-001",
			"action":   "shell",
		},
		{
			"trace_id": "trace-001",
			"span_id":  "span-002",
			"agent_id": "agent-001",
			"action":   "shell",
		},
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest/batch", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingestBatch(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ingested"].(float64) != 2 {
		t.Errorf("expected 2 ingested, got %v", resp["ingested"])
	}
}

func TestIngestBatch_PartialFailure(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	body := []map[string]interface{}{
		{
			"trace_id": "trace-001",
			"span_id":  "span-001",
			"agent_id": "agent-001",
			"action":   "shell",
		},
		{
			"trace_id": "trace-001",
			"span_id":  "span-002",
		},
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest/batch", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingestBatch(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ingested"].(float64) != 1 {
		t.Errorf("expected 1 ingested, got %v", resp["ingested"])
	}
}

func TestIngestBatch_AllInvalid(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	body := []map[string]interface{}{
		{"trace_id": "trace-001"},
		{"span_id": "span-001"},
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest/batch", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingestBatch(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestQuery_Empty(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/traces", nil)
	w := httptest.NewRecorder()

	h.query(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("expected count 0, got %v", resp["count"])
	}
}

func TestQuery_WithAgentFilter(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID:  "trace-001",
		SpanID:   "span-001",
		AgentID:  "agent-001",
		Action:   "shell",
		Decision: "allow",
	})
	s.Ingest(&models.TraceEvent{
		TraceID:  "trace-002",
		SpanID:   "span-002",
		AgentID:  "agent-002",
		Action:   "shell",
		Decision: "allow",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/traces?agent_id=agent-001", nil)
	w := httptest.NewRecorder()

	h.query(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected count 1, got %v", resp["count"])
	}
}

func TestQuery_WithDecisionFilter(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID:  "trace-001",
		SpanID:   "span-001",
		AgentID:  "agent-001",
		Action:   "shell",
		Decision: "allow",
	})
	s.Ingest(&models.TraceEvent{
		TraceID:  "trace-002",
		SpanID:   "span-002",
		AgentID:  "agent-001",
		Action:   "shell",
		Decision: "deny",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/traces?decision=allow", nil)
	w := httptest.NewRecorder()

	h.query(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected count 1, got %v", resp["count"])
	}
}

func TestQuery_WithLimit(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	for i := 0; i < 5; i++ {
		s.Ingest(&models.TraceEvent{
			TraceID: "trace-00" + string(rune('0'+i)),
			SpanID:  "span-00" + string(rune('0'+i)),
			AgentID: "agent-001",
			Action:  "shell",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/traces?limit=3", nil)
	w := httptest.NewRecorder()

	h.query(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 3 {
		t.Errorf("expected count 3, got %v", resp["count"])
	}
}

func TestGetTrace_Existing(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/traces/trace-001", nil)
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var record models.LineageRecord
	json.Unmarshal(w.Body.Bytes(), &record)
	if record.ActionDigest != "trace-001" {
		t.Errorf("expected trace-001, got %s", record.ActionDigest)
	}
}

func TestGetTrace_NotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/traces/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetTrace_EmptyID(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/traces/", nil)
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetGraph_Existing(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/traces/trace-001/graph", nil)
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var g models.TraceGraph
	json.Unmarshal(w.Body.Bytes(), &g)
}

func TestGetGraph_NotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/traces/nonexistent/graph", nil)
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetAgentLineage(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/agent-001", nil)
	w := httptest.NewRecorder()

	h.HandleAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["agent_id"] != "agent-001" {
		t.Errorf("expected agent-001, got %v", resp["agent_id"])
	}
}

func TestGetAgentLineage_WithLimit(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/agent-001?limit=5", nil)
	w := httptest.NewRecorder()

	h.HandleAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetAgentGraph(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/agent-001/graph", nil)
	w := httptest.NewRecorder()

	h.HandleAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["agent_id"] != "agent-001" {
		t.Errorf("expected agent-001, got %v", resp["agent_id"])
	}
}

func TestGetAgentLineage_NotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleAgents(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (empty lineage), got %d", w.Code)
	}
}

func TestGetAgentLineage_EmptyAgentID(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/", nil)
	w := httptest.NewRecorder()

	h.HandleAgents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestStats(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	s.Ingest(&models.TraceEvent{
		TraceID: "trace-001",
		SpanID:  "span-001",
		AgentID: "agent-001",
		Action:  "shell",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	w := httptest.NewRecorder()

	h.HandleStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total_events"].(float64) != 1 {
		t.Errorf("expected 1, got %v", resp["total_events"])
	}
}

func TestStats_MethodNotAllowed(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodPost, "/v1/stats", nil)
	w := httptest.NewRecorder()

	h.HandleStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHealth(t *testing.T) {
	h := &Handlers{Store: newObsStore()}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected ok, got %s", resp["status"])
	}
}

func TestRegister(t *testing.T) {
	h := &Handlers{Store: newObsStore()}
	mux := http.NewServeMux()
	h.Register(mux)

	routes := []string{"/health", "/v1/traces", "/v1/agents/", "/v1/stats"}
	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" || pattern == "/" {
			t.Errorf("route %s not registered", route)
		}
	}
}

func TestNewObsServer(t *testing.T) {
	s := newObsStore()
	server := NewServer(":8084", s)
	if server.Addr != ":8084" {
		t.Errorf("expected :8084, got %s", server.Addr)
	}
}

func TestHandleTraces_BatchIngest(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	body := []map[string]interface{}{
		{"trace_id": "t1", "span_id": "s1", "agent_id": "a1", "action": "x"},
		{"trace_id": "t2", "span_id": "s2", "agent_id": "a1", "action": "y"},
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest/batch", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleTraces(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestHandleTraces_PutNotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}
	req := httptest.NewRequest(http.MethodPut, "/v1/traces", nil)
	w := httptest.NewRecorder()
	h.HandleTraces(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAgents_NotFound(t *testing.T) {
	h := &Handlers{Store: newObsStore()}
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/agent-001/extra", nil)
	w := httptest.NewRecorder()
	h.HandleAgents(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestIngest_WithAllFields(t *testing.T) {
	s := newObsStore()
	h := &Handlers{Store: s}

	body := map[string]interface{}{
		"trace_id":        "trace-001",
		"span_id":         "span-001",
		"parent_span_id":  "parent-001",
		"agent_id":        "agent-001",
		"action":          "shell",
		"event_type":      "policy_evaluated",
		"resource":        "shell:ls",
		"decision":        "allow",
		"trust_score":     0.95,
		"policy_version":  "v1",
		"gateway_id":      "gw-001",
		"organization_id": "org-001",
		"duration_ns":     1000000,
		"metadata":        map[string]string{"key": "value"},
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/traces/ingest", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ingest(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}
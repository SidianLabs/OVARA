package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.observability/internal/server"
	"ovara.services.observability/internal/store"
)

func newTestServer() *httptest.Server {
	s := store.NewMemoryStore(1000)
	h := &server.Handlers{Store: s}
	mux := http.NewServeMux()
	h.Register(mux)
	return httptest.NewServer(mux)
}

func TestHealth(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
}

func TestIngestAndQuery(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	evt := map[string]any{
		"trace_id":  "trace-int-001",
		"span_id":   "span-int-001",
		"event_type": "action_requested",
		"agent_id":  "agt-int-001",
		"action":    "shell.execute",
		"resource":  "/bin/bash",
	}
	data, _ := json.Marshal(evt)

	resp, err := http.Post(ts.URL+"/v1/traces/ingest", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}

	resp2, err := http.Get(ts.URL + "/v1/traces?agent_id=agt-int-001")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp2.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp2.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestBatchIngest(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	events := []map[string]any{
		{
			"trace_id":   "trace-batch-001",
			"span_id":    "span-b1",
			"event_type": "action_requested",
			"agent_id":   "agt-batch-001",
			"action":     "shell.execute",
		},
		{
			"trace_id":   "trace-batch-001",
			"span_id":    "span-b2",
			"event_type": "action_executed",
			"agent_id":   "agt-batch-001",
			"action":     "shell.execute",
			"decision":   "allow",
		},
	}
	data, _ := json.Marshal(events)

	resp, err := http.Post(ts.URL+"/v1/traces/ingest/batch", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Batch ingest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["ingested"].(float64) != 2 {
		t.Errorf("ingested = %v, want 2", result["ingested"])
	}
}

func TestGetTraceAndGraph(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	events := []map[string]any{
		{
			"trace_id":   "trace-graph-001",
			"span_id":    "span-g1",
			"event_type": "action_requested",
			"agent_id":   "agt-graph-001",
			"action":     "shell.execute",
		},
		{
			"trace_id":   "trace-graph-001",
			"span_id":    "span-g2",
			"event_type": "action_executed",
			"agent_id":   "agt-graph-001",
			"action":     "shell.execute",
		},
	}
	data, _ := json.Marshal(events)
	http.Post(ts.URL+"/v1/traces/ingest/batch", "application/json", bytes.NewReader(data))

	resp, err := http.Get(ts.URL + "/v1/traces/trace-graph-001")
	if err != nil {
		t.Fatalf("GetTrace failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	resp2, err := http.Get(ts.URL + "/v1/traces/trace-graph-001/graph")
	if err != nil {
		t.Fatalf("GetGraph failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp2.StatusCode)
	}

	var graph map[string]any
	json.NewDecoder(resp2.Body).Decode(&graph)
	nodes := graph["nodes"].([]any)
	if len(nodes) != 2 {
		t.Errorf("nodes = %d, want 2", len(nodes))
	}
}

func TestStats(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	evt := map[string]any{
		"trace_id":  "trace-stats-001",
		"span_id":   "span-s1",
		"event_type": "action_requested",
		"agent_id":  "agt-stats-001",
		"action":    "shell.execute",
	}
	data, _ := json.Marshal(evt)
	http.Post(ts.URL+"/v1/traces/ingest", "application/json", bytes.NewReader(data))

	resp, err := http.Get(ts.URL + "/v1/stats")
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["total_events"].(float64) != 1 {
		t.Errorf("total_events = %v, want 1", result["total_events"])
	}
}

func TestAgentLineage(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	evt := map[string]any{
		"trace_id":   "trace-agent-001",
		"span_id":    "span-a1",
		"event_type": "action_requested",
		"agent_id":   "agt-lineage-001",
		"action":     "shell.execute",
	}
	data, _ := json.Marshal(evt)
	http.Post(ts.URL+"/v1/traces/ingest", "application/json", bytes.NewReader(data))

	resp, err := http.Get(ts.URL + "/v1/agents/agt-lineage-001/lineage")
	if err != nil {
		t.Fatalf("Agent lineage failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestIngestMissingFields(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	evt := map[string]any{
		"trace_id": "trace-missing-001",
	}
	data, _ := json.Marshal(evt)

	resp, err := http.Post(ts.URL+"/v1/traces/ingest", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

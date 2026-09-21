package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.approval/internal/server"
	"ovara.services.approval/internal/store"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := store.NewMemoryStore(0)
	h := &server.Handlers{Store: s}
	mux := http.NewServeMux()
	h.Register(mux)
	return httptest.NewServer(mux)
}

func TestHealthEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %s", body["status"])
	}
}

func TestCreateAndGetApproval(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"gateway_id":"gw-1","decision_id":"dec-1","action_type":"execute","resource":"db:drop","requested_by":"admin"}`
	resp, err := http.Post(ts.URL+"/v1/approvals", "application/json", bytes.NewBufferString(createBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	id := created["id"].(string)

	resp2, err := http.Get(ts.URL + "/v1/approvals/" + id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var got map[string]any
	json.NewDecoder(resp2.Body).Decode(&got)
	if got["state"] != "pending" {
		t.Errorf("expected state pending, got %s", got["state"])
	}
}

func TestApproveApproval(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"gateway_id":"gw-1","decision_id":"dec-2","action_type":"execute","resource":"db:drop","requested_by":"admin"}`
	resp, _ := http.Post(ts.URL+"/v1/approvals", "application/json", bytes.NewBufferString(createBody))
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	id := created["id"].(string)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/"+id+"/approve", bytes.NewBufferString(`{"resolved_by":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var approved map[string]any
	json.NewDecoder(resp2.Body).Decode(&approved)
	if approved["state"] != "approved" {
		t.Errorf("expected state approved, got %s", approved["state"])
	}
}

func TestDenyApproval(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"gateway_id":"gw-1","decision_id":"dec-3","action_type":"execute","resource":"db:drop","requested_by":"admin"}`
	resp, _ := http.Post(ts.URL+"/v1/approvals", "application/json", bytes.NewBufferString(createBody))
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	id := created["id"].(string)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/"+id+"/deny", bytes.NewBufferString(`{"reason":"not allowed","resolved_by":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var denied map[string]any
	json.NewDecoder(resp2.Body).Decode(&denied)
	if denied["state"] != "denied" {
		t.Errorf("expected state denied, got %s", denied["state"])
	}
}

func TestListApprovals(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := `{"gateway_id":"gw-list","decision_id":"dec-list","requested_by":"admin"}`
		http.Post(ts.URL+"/v1/approvals", "application/json", bytes.NewBufferString(body))
	}

	resp, err := http.Get(ts.URL + "/v1/approvals?gateway_id=gw-list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	count := int(result["count"].(float64))
	if count != 3 {
		t.Errorf("expected 3 approvals, got %d", count)
	}
}

func TestStatsEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/approvals/stats")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var stats map[string]any
	json.NewDecoder(resp.Body).Decode(&stats)
	total := int(stats["total"].(float64))
	if total != 0 {
		t.Errorf("expected 0 total, got %d", total)
	}
}

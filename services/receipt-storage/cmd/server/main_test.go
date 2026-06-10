package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.receipt/internal/server"
	"ovara.services.receipt/internal/store"
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

func TestArchiveAndGetReceipt(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"decision_id":"dec-1","gateway_id":"gw-1","organization_id":"org-1","action_type":"execute","resource":"db:drop","decision":"allow","trust_score":0.9,"payload":"test","signature":"abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}`
	resp, err := http.Post(ts.URL+"/v1/receipts", "application/json", bytes.NewBufferString(createBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	id := created["id"].(string)

	resp2, err := http.Get(ts.URL + "/v1/receipts/" + id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var got map[string]any
	json.NewDecoder(resp2.Body).Decode(&got)
	if got["decision_id"] != "dec-1" {
		t.Errorf("expected decision_id dec-1, got %s", got["decision_id"])
	}
}

func TestVerifyReceipt(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"decision_id":"dec-v","gateway_id":"gw-v","organization_id":"org-v","action_type":"execute","resource":"db:drop","decision":"allow","trust_score":0.95,"payload":"test","signature":"a"}`
	resp, _ := http.Post(ts.URL+"/v1/receipts", "application/json", bytes.NewBufferString(createBody))
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	id := created["id"].(string)

	resp2, err := http.Get(ts.URL + "/v1/receipts/" + id + "/verify")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var result map[string]any
	json.NewDecoder(resp2.Body).Decode(&result)
	if result["valid"] != false {
		t.Errorf("expected valid false for short signature, got %v", result["valid"])
	}
}

func TestListReceipts(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := `{"decision_id":"dec-list","gateway_id":"gw-list","organization_id":"org-list","action_type":"execute","resource":"test","decision":"allow","trust_score":0.5,"payload":"p","signature":"a"}`
		http.Post(ts.URL+"/v1/receipts", "application/json", bytes.NewBufferString(body))
	}

	resp, err := http.Get(ts.URL + "/v1/receipts?gateway_id=gw-list")
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
		t.Errorf("expected 3 receipts, got %d", count)
	}
}

func TestStatsEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/receipts/stats")
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

func TestStatsWithOrgFilter(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	body := `{"decision_id":"dec-org","gateway_id":"gw","organization_id":"org-x","action_type":"execute","resource":"test","decision":"allow","trust_score":0.5,"payload":"p","signature":"a"}`
	http.Post(ts.URL+"/v1/receipts", "application/json", bytes.NewBufferString(body))

	resp, err := http.Get(ts.URL + "/v1/receipts/stats?organization_id=org-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var stats map[string]any
	json.NewDecoder(resp.Body).Decode(&stats)
	orgCount := int(stats["organization_count"].(float64))
	if orgCount != 1 {
		t.Errorf("expected 1 org count, got %d", orgCount)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.alerting/internal/engine"
	"ovara.services.alerting/internal/server"
	"ovara.services.alerting/internal/store"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := store.NewMemoryStore(0)
	e := engine.New(s)
	h := &server.Handlers{Engine: e}
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

func TestIngestAndGetAlert(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	ingestBody := `{"type":"anomaly","severity":"high","agent_id":"agt-001","gateway_id":"gw-001","organization_id":"org-001","action":"shell.execute","resource":"sudo","trust_score":0.2,"message":"suspicious activity"}`
	resp, err := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(ingestBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	alertData := created["alert"].(map[string]any)
	id := alertData["id"].(string)

	resp2, err := http.Get(ts.URL + "/v1/alerts/" + id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var got map[string]any
	json.NewDecoder(resp2.Body).Decode(&got)
	if got["state"] != "new" {
		t.Errorf("expected state new, got %s", got["state"])
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	ingestBody := `{"type":"anomaly","severity":"critical","agent_id":"agt-002","message":"critical event"}`
	resp, _ := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(ingestBody))
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	alertData := created["alert"].(map[string]any)
	id := alertData["id"].(string)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/alerts/"+id+"/acknowledge", bytes.NewBufferString(`{"acknowledged_by":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var acked map[string]any
	json.NewDecoder(resp2.Body).Decode(&acked)
	if acked["state"] != "acknowledged" {
		t.Errorf("expected state acknowledged, got %s", acked["state"])
	}
}

func TestResolveAlert(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	ingestBody := `{"type":"containment","severity":"high","agent_id":"agt-003","message":"containment event"}`
	resp, _ := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(ingestBody))
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	alertData := created["alert"].(map[string]any)
	id := alertData["id"].(string)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/alerts/"+id+"/resolve", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	var resolved map[string]any
	json.NewDecoder(resp2.Body).Decode(&resolved)
	if resolved["state"] != "resolved" {
		t.Errorf("expected state resolved, got %s", resolved["state"])
	}
}

func TestListAlerts(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := `{"type":"anomaly","severity":"medium","agent_id":"agt-list","gateway_id":"gw-list","resource":"res-` + string(rune('a'+i)) + `","message":"test alert"}`
		http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(body))
	}

	resp, err := http.Get(ts.URL + "/v1/alerts?agent_id=agt-list")
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
		t.Errorf("expected 3 alerts, got %d", count)
	}
}

func TestCRUDRules(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	createBody := `{"name":"Test Rule","condition":"trust_below","threshold":0.5,"window_seconds":300,"severity":"critical","enabled":true}`
	resp, err := http.Post(ts.URL+"/v1/alerts/rules", "application/json", bytes.NewBufferString(createBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	ruleID := created["id"].(string)

	resp2, err := http.Get(ts.URL + "/v1/alerts/rules")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var rulesResult map[string]any
	json.NewDecoder(resp2.Body).Decode(&rulesResult)
	rulesCount := int(rulesResult["count"].(float64))
	if rulesCount != 1 {
		t.Errorf("expected 1 rule, got %d", rulesCount)
	}

	updateBody := `{"name":"Updated Rule","threshold":0.3}`
	updateReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/alerts/rules/"+ruleID, bytes.NewBufferString(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	resp3, err := http.DefaultClient.Do(updateReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp3.StatusCode)
	}

	deleteReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/v1/alerts/rules/"+ruleID, nil)
	resp4, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp4.StatusCode)
	}

	resp5, _ := http.Get(ts.URL + "/v1/alerts/rules")
	var afterDelete map[string]any
	json.NewDecoder(resp5.Body).Decode(&afterDelete)
	if int(afterDelete["count"].(float64)) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", int(afterDelete["count"].(float64)))
	}
}

func TestStatsEndpoint(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	body := `{"type":"anomaly","severity":"critical","agent_id":"agt-stats","message":"stats test"}`
	http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(body))

	resp, err := http.Get(ts.URL + "/v1/alerts/stats")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var stats map[string]any
	json.NewDecoder(resp.Body).Decode(&stats)
	total := int(stats["total"].(float64))
	if total != 1 {
		t.Errorf("expected 1 total alert, got %d", total)
	}
}

func TestIngestMissingType(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	body := `{"severity":"high","message":"no type"}`
	resp, err := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetAlertNotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/alerts/nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDuplicateIngest(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	body := `{"type":"anomaly","severity":"high","agent_id":"agt-dup","gateway_id":"gw-dup","resource":"r-dup","message":"dup test"}`
	resp1, _ := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(body))
	if resp1.StatusCode != http.StatusCreated {
		t.Errorf("first ingest: expected 201, got %d", resp1.StatusCode)
	}

	resp2, _ := http.Post(ts.URL+"/v1/alerts/ingest", "application/json", bytes.NewBufferString(body))
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate ingest: expected 409, got %d", resp2.StatusCode)
	}
}

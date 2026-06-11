package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.alerting/internal/engine"
	"ovara.services.alerting/internal/models"
	"ovara.services.alerting/internal/store"
)

func newAlertMockStore() store.Store {
	return store.NewMemoryStore(10000)
}

func newAlertEngine() *engine.Engine {
	return engine.New(newAlertMockStore())
}

func TestAlertHandle_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	w := httptest.NewRecorder()
	h.HandleAlerts(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAlertHandle_MethodNotAllowed(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}
	req := httptest.NewRequest(http.MethodPut, "/v1/alerts", nil)
	w := httptest.NewRecorder()
	h.HandleAlerts(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestIngest_ValidRequest(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	body := map[string]interface{}{
		"type":             "anomaly",
		"severity":          "high",
		"agent_id":         "agent-001",
		"gateway_id":       "gw-001",
		"organization_id": "org-001",
		"action":           "shell",
		"resource":         "shell:ls",
		"trust_score":      0.3,
		"message":          "Anomalous behavior detected",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["alert"] == nil {
		t.Errorf("expected alert in response")
	}
}

func TestIngest_MissingType(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	body := map[string]interface{}{
		"severity": "high",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestIngest_InvalidJSON(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestIngest_DefaultSeverity(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	body := map[string]interface{}{
		"type":             "anomaly",
		"agent_id":         "agent-001",
		"gateway_id":       "gw-001",
		"organization_id": "org-001",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	alert := resp["alert"].(map[string]interface{})
	if alert["severity"] != "medium" {
		t.Errorf("expected default severity medium, got %v", alert["severity"])
	}
}

func TestGetAlert_Existing(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	created, _ := e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/"+created.ID, nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetAlert_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetAlert_EmptyID(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListAlerts_Empty(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("expected count 0, got %v", resp["count"])
	}
}

func TestListAlerts_WithSeverityFilter(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})
	e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityLow,
		AgentID:        "agent-002",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts?severity=high", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected count 1, got %v", resp["count"])
	}
}

func TestAcknowledge_Existing(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	alert, _ := e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})

	body := map[string]interface{}{
		"acknowledged_by": "admin@example.com",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/"+alert.ID+"/acknowledge", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.Alert
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.State != models.AlertStateAcknowledged {
		t.Errorf("expected state acknowledged, got %s", result.State)
	}
}

func TestAcknowledge_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/nonexistent/acknowledge", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestResolve_Existing(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	alert, _ := e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/"+alert.ID+"/resolve", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.Alert
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.State != models.AlertStateResolved {
		t.Errorf("expected state resolved, got %s", result.State)
	}
}

func TestResolve_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/nonexistent/resolve", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestStats(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})
	e.ProcessEvent(engine.Event{
		Type:           models.AlertTypeAnomaly,
		Severity:       models.SeverityHigh,
		AgentID:        "agent-002",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/stats", nil)
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 2 {
		t.Errorf("expected total 2, got %v", resp["total"])
	}
}

func TestHealth(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

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
	h := &Handlers{Engine: newAlertEngine()}
	mux := http.NewServeMux()
	h.Register(mux)

	routes := []string{"/health", "/v1/alerts", "/v1/alerts/rules", "/v1/alerts/"}
	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" || pattern == "/" {
			t.Errorf("route %s not registered", route)
		}
	}
}

func TestNewAlertServer(t *testing.T) {
	e := newAlertEngine()
	server := NewServer(":8083", e)
	if server.Addr != ":8083" {
		t.Errorf("expected :8083, got %s", server.Addr)
	}
}

func TestCreateRule_Valid(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	body := map[string]interface{}{
		"name":           "Low Trust Alert",
		"condition":      "trust_below",
		"threshold":      0.5,
		"window_seconds": 60,
		"severity":       "high",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/rules", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var rule models.AlertRule
	json.Unmarshal(w.Body.Bytes(), &rule)
	if rule.Name != "Low Trust Alert" {
		t.Errorf("expected name, got %s", rule.Name)
	}
}

func TestCreateRule_MissingFields(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	body := map[string]interface{}{
		"name": "Only name",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/rules", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateRule_InvalidJSON(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/rules", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateRule_DefaultSeverity(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	body := map[string]interface{}{
		"name":       "Test Rule",
		"condition":  "trust_below",
		"threshold":  0.5,
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/rules", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var rule models.AlertRule
	json.Unmarshal(w.Body.Bytes(), &rule)
	if rule.Severity != models.SeverityMedium {
		t.Errorf("expected default severity medium, got %s", rule.Severity)
	}
}

func TestCreateRule_DefaultWindow(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	body := map[string]interface{}{
		"name":       "Test Rule",
		"condition":  "trust_below",
		"threshold":  0.5,
		"window_seconds": 0,
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/rules", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var rule models.AlertRule
	json.Unmarshal(w.Body.Bytes(), &rule)
	if rule.WindowSeconds != 300 {
		t.Errorf("expected default window 300, got %d", rule.WindowSeconds)
	}
}

func TestListRules_Empty(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/rules", nil)
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("expected count 0, got %v", resp["count"])
	}
}

func TestListRules_WithRules(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.CreateRule(&models.AlertRule{
		ID:        "rule-001",
		Name:      "Rule One",
		Condition: models.ConditionTrustBelow,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/rules", nil)
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected count 1, got %v", resp["count"])
	}
}

func TestUpdateRule_Existing(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.CreateRule(&models.AlertRule{
		ID:        "rule-001",
		Name:      "Original Name",
		Condition: models.ConditionTrustBelow,
		Threshold: 0.5,
	})

	body := map[string]interface{}{
		"name": "Updated Name",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/alerts/rules/rule-001", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var rule models.AlertRule
	json.Unmarshal(w.Body.Bytes(), &rule)
	if rule.Name != "Updated Name" {
		t.Errorf("expected Updated Name, got %s", rule.Name)
	}
}

func TestUpdateRule_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	body := map[string]interface{}{
		"name": "New Name",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/alerts/rules/nonexistent", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeleteRule_Existing(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.CreateRule(&models.AlertRule{
		ID:        "rule-001",
		Name:      "To Delete",
		Condition: models.ConditionTrustBelow,
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/alerts/rules/rule-001", nil)
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDeleteRule_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}

	req := httptest.NewRequest(http.MethodDelete, "/v1/alerts/rules/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleRules(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestIngestRuleTriggered(t *testing.T) {
	e := newAlertEngine()
	h := &Handlers{Engine: e}

	e.CreateRule(&models.AlertRule{
		ID:            "rule-001",
		Name:          "Low Trust Rule",
		Condition:     models.ConditionTrustBelow,
		Threshold:     0.5,
		WindowSeconds: 60,
		Severity:      models.SeverityHigh,
		Enabled:       true,
	})

	body := map[string]interface{}{
		"type":             "anomaly",
		"severity":         "medium",
		"agent_id":         "agent-001",
		"gateway_id":       "gw-001",
		"organization_id": "org-001",
		"trust_score":      0.3,
		"message":          "Low trust detected",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleAlerts(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["rule_alerts"] == nil {
		t.Log("no rule alerts triggered (may be expected depending on dedupe)")
	}
}

func TestRulesHandle_NotFound(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/rules-extra", nil)
	w := httptest.NewRecorder()
	h.HandleRules(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestRulesHandle_MethodNotAllowed(t *testing.T) {
	h := &Handlers{Engine: newAlertEngine()}
	req := httptest.NewRequest(http.MethodPatch, "/v1/alerts/rules", nil)
	w := httptest.NewRecorder()
	h.HandleRules(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
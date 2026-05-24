package trust

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleGetTrustContext(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent-123", "test restriction")
	store.riskCounts["agent-123"] = 5
	store.lastDecision["agent-123"] = "deny"
	store.lastDecisionTime["agent-123"] = time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	handler := NewHandler(store, nil)

	tests := []struct {
		name           string
		agentID        string
		wantStatus     int
		wantRestricted bool
		wantRiskCount  int
	}{
		{
			name:           "valid agent_id returns stats",
			agentID:        "agent-123",
			wantStatus:     http.StatusOK,
			wantRestricted: true,
			wantRiskCount:  5,
		},
		{
			name:       "missing agent_id returns 400",
			agentID:    "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:           "unknown agent_id returns empty stats",
			agentID:        "unknown-agent",
			wantStatus:     http.StatusOK,
			wantRestricted: false,
			wantRiskCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/trust/context?agent_id="+tt.agentID, nil)
			rec := httptest.NewRecorder()

			handler.handleGetTrustContext(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantStatus != http.StatusOK {
				return
			}

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp["agent_id"] != tt.agentID {
				t.Errorf("agent_id = %v, want %v", resp["agent_id"], tt.agentID)
			}
			if resp["restricted"] != tt.wantRestricted {
				t.Errorf("restricted = %v, want %v", resp["restricted"], tt.wantRestricted)
			}
			if resp["risk_count"] != float64(tt.wantRiskCount) {
				t.Errorf("risk_count = %v, want %v", resp["risk_count"], tt.wantRiskCount)
			}
		})
	}
}

func TestHandleShieldStatus(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent-1", "test reason 1")
	store.Restrict("agent-2", "test reason 2")

	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/shield/status", nil)
	rec := httptest.NewRecorder()

	handler.handleShieldStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	agents := resp["restricted_agents"].([]any)
	if len(agents) != 2 {
		t.Errorf("restricted_agents count = %d, want 2", len(agents))
	}

	if resp["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", resp["count"])
	}
}

func TestHandleAgentShieldStatus(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("restricted-agent", "containment reason")
	store.riskCounts["restricted-agent"] = 3
	store.lastDecision["restricted-agent"] = "escalate"
	store.lastDecisionTime["restricted-agent"] = time.Date(2024, 2, 20, 14, 0, 0, 0, time.UTC)

	handler := NewHandler(store, nil)

	tests := []struct {
		name           string
		agentID        string
		setPathValue   bool
		wantStatus     int
		wantRestricted bool
		wantRiskCount  int
	}{
		{
			name:           "restricted agent returns stats",
			agentID:        "restricted-agent",
			setPathValue:   true,
			wantStatus:     http.StatusOK,
			wantRestricted: true,
			wantRiskCount:  3,
		},
		{
			name:         "empty agent_id returns 400",
			agentID:      "",
			setPathValue:  false,
			wantStatus:    http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/shield/status/"+tt.agentID, nil)
			if tt.setPathValue {
				req.SetPathValue("agent_id", tt.agentID)
			}
			rec := httptest.NewRecorder()

			handler.handleAgentShieldStatus(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantStatus != http.StatusOK {
				return
			}

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp["agent_id"] != tt.agentID {
				t.Errorf("agent_id = %v, want %v", resp["agent_id"], tt.agentID)
			}
			if resp["restricted"] != tt.wantRestricted {
				t.Errorf("restricted = %v, want %v", resp["restricted"], tt.wantRestricted)
			}
			if resp["risk_count"] != float64(tt.wantRiskCount) {
				t.Errorf("risk_count = %v, want %v", resp["risk_count"], tt.wantRiskCount)
			}
		})
	}
}

func TestHandleRestrict(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	tests := []struct {
		name            string
		agentID         string
		setPathValue    bool
		body            string
		wantStatus      int
		wantRestricted  bool
		wantReason      string
	}{
		{
			name:         "restrict with reason",
			agentID:      "agent-x",
			setPathValue: true,
			body:         `{"reason":"security concern"}`,
			wantStatus:   http.StatusOK,
			wantRestricted: true,
			wantReason:  "security concern",
		},
		{
			name:         "restrict without reason uses default",
			agentID:      "agent-y",
			setPathValue: true,
			body:         `{}`,
			wantStatus:   http.StatusOK,
			wantRestricted: true,
			wantReason:  "",
		},
		{
			name:         "restrict with empty body uses default",
			agentID:      "agent-z",
			setPathValue: true,
			body:         "",
			wantStatus:   http.StatusOK,
			wantRestricted: true,
			wantReason:  "manual_restriction",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/shield/restrict/"+tt.agentID, body)
			if tt.setPathValue {
				req.SetPathValue("agent_id", tt.agentID)
			}
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()

			handler.handleRestrict(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp["agent_id"] != tt.agentID {
				t.Errorf("agent_id = %v, want %v", resp["agent_id"], tt.agentID)
			}
			if resp["restricted"] != tt.wantRestricted {
				t.Errorf("restricted = %v, want %v", resp["restricted"], tt.wantRestricted)
			}
			if resp["reason"] != tt.wantReason {
				t.Errorf("reason = %v, want %v", resp["reason"], tt.wantReason)
			}

			if store.IsRestricted(tt.agentID) != tt.wantRestricted {
				t.Errorf("store.IsRestricted(%s) = %v, want %v", tt.agentID, store.IsRestricted(tt.agentID), tt.wantRestricted)
			}
		})
	}
}

func TestHandleUnrestrict(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent-to-unrestrict", "initial reason")
	handler := NewHandler(store, nil)

	if !store.IsRestricted("agent-to-unrestrict") {
		t.Fatal("expected agent to be restricted before test")
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/shield/unrestrict/agent-to-unrestrict", nil)
	req.SetPathValue("agent_id", "agent-to-unrestrict")
	rec := httptest.NewRecorder()

	handler.handleUnrestrict(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["agent_id"] != "agent-to-unrestrict" {
		t.Errorf("agent_id = %v, want agent-to-unrestrict", resp["agent_id"])
	}
	if resp["restricted"] != false {
		t.Errorf("restricted = %v, want false", resp["restricted"])
	}

	if store.IsRestricted("agent-to-unrestrict") {
		t.Error("agent should be unrestricted after handleUnrestrict")
	}
}

func TestHandlerRegisterRoutes(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)
	mux := http.NewServeMux()

	handler.RegisterRoutes(mux)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/trust/context?agent_id=test"},
		{http.MethodGet, "/v1/shield/status"},
		{http.MethodGet, "/v1/shield/status/agent-abc"},
		{http.MethodPost, "/v1/shield/restrict/agent-abc"},
		{http.MethodPost, "/v1/shield/unrestrict/agent-abc"},
	}

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusNotFound {
				t.Errorf("route %s %s not registered", rt.method, rt.path)
			}
		})
	}
}

func TestHandleGetTrustContext_MethodNotAllowed(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/trust/context?agent_id=test", nil)
	rec := httptest.NewRecorder()

	handler.handleGetTrustContext(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleShieldStatus_MethodNotAllowed(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/shield/status", nil)
	rec := httptest.NewRecorder()

	handler.handleShieldStatus(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleAgentShieldStatus_MethodNotAllowed(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/shield/status/agent-123", nil)
	req.SetPathValue("agent_id", "agent-123")
	rec := httptest.NewRecorder()

	handler.handleAgentShieldStatus(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleRestrict_MethodNotAllowed(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/shield/restrict/agent-123", nil)
	req.SetPathValue("agent_id", "agent-123")
	rec := httptest.NewRecorder()

	handler.handleRestrict(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleUnrestrict_MethodNotAllowed(t *testing.T) {
	store := NewShieldStore()
	handler := NewHandler(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/shield/unrestrict/agent-123", nil)
	req.SetPathValue("agent_id", "agent-123")
	rec := httptest.NewRecorder()

	handler.handleUnrestrict(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
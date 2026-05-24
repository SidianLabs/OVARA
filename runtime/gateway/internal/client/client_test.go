package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestGatewayClient_CheckOptionIdentity(t *testing.T) {
	identity := &models.AgentIdentity{
		Issuer:    "test",
		SubjectID: "agent-001",
	}

	opt := WithIdentity(identity)
	req := models.ActionRequest{}

	opt(&req)

	if req.AgentIdentity == nil {
		t.Fatal("agent identity is nil")
	}
	if req.AgentIdentity.SubjectID != "agent-001" {
		t.Errorf("subject_id = %v, want agent-001", req.AgentIdentity.SubjectID)
	}
}

func TestGatewayClient_CheckOptionLease(t *testing.T) {
	lease := &models.CapabilityLease{
		LeaseID: "cap_123",
		Subject: "agent-001",
	}

	opt := WithLease(lease)
	req := models.ActionRequest{}

	opt(&req)

	if req.CapabilityLease == nil {
		t.Fatal("capability lease is nil")
	}
	if req.CapabilityLease.LeaseID != "cap_123" {
		t.Errorf("lease_id = %v, want cap_123", req.CapabilityLease.LeaseID)
	}
}

func TestGatewayClient_CheckOptionMetadata(t *testing.T) {
	metadata := map[string]any{
		"key": "value",
	}

	opt := WithMetadata(metadata)
	req := models.ActionRequest{}

	opt(&req)

	if req.Metadata == nil {
		t.Fatal("metadata is nil")
	}
}

func TestGatewayClient_Check_ReturnsDecision(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime/check" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		resp := models.DecisionResponse{
			DecisionID: "dec_test123",
			Decision:   models.DecisionAllow,
			ReasonCodes: []models.ReasonCode{models.ReasonAllowed},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	gc := NewGatewayClient(ts.URL, "test-agent")
	resp, err := gc.Check(models.ActionTypeGitPull, "repo:acme/api", models.EnvironmentLocal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != models.DecisionAllow {
		t.Errorf("decision = %v, want allow", resp.Decision)
	}
	if resp.DecisionID != "dec_test123" {
		t.Errorf("decision_id = %v, want dec_test123", resp.DecisionID)
	}
}

func TestGatewayClient_Check_Escalate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			DecisionID:       "dec_esc456",
			Decision:         models.DecisionEscalate,
			ReasonCodes:      []models.ReasonCode{models.ReasonEscalate},
			RequiresApproval: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	gc := NewGatewayClient(ts.URL, "test-agent")
	resp, err := gc.Check(models.ActionTypeShell, "shell:echo test", models.EnvironmentLocal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != models.DecisionEscalate {
		t.Errorf("decision = %v, want escalate", resp.Decision)
	}
	if !resp.RequiresApproval {
		t.Error("requires_approval should be true")
	}
}

func TestGatewayClient_Allow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			Decision: models.DecisionAllow,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	gc := NewGatewayClient(ts.URL, "test-agent")
	allowed, err := gc.Allow(models.ActionTypeGitPull, "repo:acme/api", models.EnvironmentLocal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allow to return true")
	}
}

func TestGatewayClient_Allow_DenyReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.DecisionResponse{
			Decision: models.DecisionDeny,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	gc := NewGatewayClient(ts.URL, "test-agent")
	allowed, err := gc.Allow(models.ActionTypeShell, "shell:echo test", models.EnvironmentLocal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected deny to return false")
	}
}
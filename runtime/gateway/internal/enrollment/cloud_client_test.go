package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudService_Enroll(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/gateways/enroll" && r.Method == http.MethodPost {
			called = true
			if r.Header.Get("Authorization") != "Bearer test-api-key" {
				t.Error("missing or incorrect Authorization header")
			}
			resp := enrollResponse{
				ID:              "gw-enrolled-001",
				Status:          "enrolling",
				EnrollmentToken: "ovara_enr_testtoken123",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	svc := NewCloudService("", CloudConfig{
		ControlPlaneURL:    server.URL,
		ControlPlaneAPIKey: "test-api-key",
	}, WithGatewayName("cloud-gw"))
	err := svc.Initialize("local")

	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = svc.Enroll("org-123")
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !called {
		t.Error("server was not called")
	}

	id := svc.GetIdentity()
	if id.ID != "gw-enrolled-001" {
		t.Errorf("identity.ID = %v, want gw-enrolled-001", id.ID)
	}
	if id.EnrollmentState != EnrollmentStateEnrolled {
		t.Errorf("enrollment state = %v, want enrolled", id.EnrollmentState)
	}
}

func TestCloudService_Enroll_FailureStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer server.Close()

	svc := NewCloudService("", CloudConfig{
		ControlPlaneURL:    server.URL,
		ControlPlaneAPIKey: "bad-key",
	})
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = svc.Enroll("org-123")
	if err == nil {
		t.Error("expected enrollment error for 401 status")
	}
}

func TestCloudService_ConfirmEnrollment(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/gateways/confirm/gw-001" && r.Method == http.MethodPost {
			called = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	svc := NewCloudService("", CloudConfig{
		ControlPlaneURL:    server.URL,
		ControlPlaneAPIKey: "key",
	})
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	svc.identity.ID = "gw-001"

	err = svc.ConfirmEnrollment("token")
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}
	if !called {
		t.Error("confirm endpoint was not called")
	}
}

func TestCloudService_CloudHeartbeat(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/gateways/gw-hb-001/heartbeat" && r.Method == http.MethodPost {
			called = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	svc := NewCloudService("", CloudConfig{
		ControlPlaneURL:    server.URL,
		ControlPlaneAPIKey: "key",
	})
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	svc.identity.ID = "gw-hb-001"
	before := svc.GetIdentity().LastSeenAt

	err = svc.CloudHeartbeat()
	if err != nil {
		t.Fatalf("CloudHeartbeat failed: %v", err)
	}
	if !called {
		t.Error("heartbeat endpoint was not called")
	}
	if !svc.GetIdentity().LastSeenAt.After(before) {
		t.Error("LastSeenAt not updated after cloud heartbeat")
	}
}

func TestPolicySyncService_FetchDistributions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/policies/distributions/gw-sync-001" {
			items := []distributionItem{
				{ID: "d1", PolicyID: "p1", GatewayID: "gw-sync-001", Status: "pending"},
				{ID: "d2", PolicyID: "p2", GatewayID: "gw-sync-001", Status: "delivered"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(items)
		}
	}))
	defer server.Close()

	syncer := NewPolicySyncService(server.URL, "key", "gw-sync-001")
	items, err := syncer.FetchDistributions()
	if err != nil {
		t.Fatalf("FetchDistributions failed: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("got %d distributions, want 2", len(items))
	}
	if items[0].PolicyID != "p1" {
		t.Errorf("item[0].PolicyID = %v, want p1", items[0].PolicyID)
	}
}

func TestPolicySyncService_FetchPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/policies/p-test-001" {
			item := policySyncResponse{
				ID:      "p-test-001",
				Name:    "block-sudo",
				Version: 3,
				Rules:   json.RawMessage(`[{"id":"r1","action":"shell.execute","target":"sudo","effect":"deny","priority":100}]`),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(item)
		}
	}))
	defer server.Close()

	syncer := NewPolicySyncService(server.URL, "key", "gw-001")
	policy, err := syncer.FetchPolicy("p-test-001")
	if err != nil {
		t.Fatalf("FetchPolicy failed: %v", err)
	}
	if policy.Name != "block-sudo" {
		t.Errorf("policy.Name = %v, want block-sudo", policy.Name)
	}
	if policy.Version != 3 {
		t.Errorf("policy.Version = %v, want 3", policy.Version)
	}
	if policy.Rules == nil {
		t.Error("policy.Rules is nil")
	}
	if syncer.LastSyncAt().IsZero() {
		t.Error("LastSyncAt should not be zero after FetchPolicy")
	}
}

func TestPolicySyncService_FetchPolicy_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	syncer := NewPolicySyncService(server.URL, "key", "gw-001")
	_, err := syncer.FetchPolicy("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent policy")
	}
}

func TestCloudService_EnrollmentPersistsToDisk(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := tmpDir + "/enrollment.json"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := enrollResponse{
			ID:              "gw-persist-001",
			Status:          "enrolling",
			EnrollmentToken: "token",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewCloudService(filePath, CloudConfig{
		ControlPlaneURL:    server.URL,
		ControlPlaneAPIKey: "key",
	}, WithGatewayName("persist-gw"))
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = svc.Enroll("org-456")
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	svc2 := NewLocalService(filePath)
	err = svc2.Initialize("local")
	if err != nil {
		t.Fatalf("second Initialize failed: %v", err)
	}
	id := svc2.GetIdentity()
	if id.ID != "gw-persist-001" {
		t.Errorf("persisted ID = %v, want gw-persist-001", id.ID)
	}
}

func TestCloudConfig_Defaults(t *testing.T) {
	cfg := CloudConfig{}
	if cfg.ControlPlaneURL != "" {
		t.Errorf("ControlPlaneURL should default to empty")
	}
	if cfg.PolicySource != "" {
		t.Errorf("PolicySource should default to empty")
	}
}

func TestEnrollmentEnrolledState(t *testing.T) {
	svc := NewLocalService("")
	err := svc.Initialize("local")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if svc.IsEnrolled() {
		t.Error("local service should not report enrolled")
	}
}

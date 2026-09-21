package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/models"
)

func TestCapabilitiesHandler_HandleGet_PathParam(t *testing.T) {
	store := capabilities.NewInMemoryStore()
	lease := &models.CapabilityLease{
		LeaseID: "lease_abc123",
		Subject: "agent-1",
		Issuer:  "gateway-1",
		Expiry:  time.Now().Add(1 * time.Hour),
	}
	store.Track(lease, "gw1")

	h := NewCapabilitiesHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities/lease_abc123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["lease"] == nil {
		t.Errorf("lease field missing from response")
	}
}

func TestCapabilitiesHandler_HandleGet_NotFound(t *testing.T) {
	store := capabilities.NewInMemoryStore()
	h := NewCapabilitiesHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["error"] != "capability not found: nonexistent" {
		t.Errorf("error = %v, want 'capability not found: nonexistent'", resp["error"])
	}
}

func TestCapabilitiesHandler_HandleList(t *testing.T) {
	store := capabilities.NewInMemoryStore()
	lease := &models.CapabilityLease{
		LeaseID: "lease_abc123",
		Subject: "agent-1",
		Issuer:  "gateway-1",
		Expiry:  time.Now().Add(1 * time.Hour),
	}
	store.Track(lease, "gw1")

	h := NewCapabilitiesHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["capabilities"] == nil {
		t.Errorf("capabilities field missing from response")
	}
}

func TestCapabilitiesHandler_HandleGet_WrongMethod(t *testing.T) {
	store := capabilities.NewInMemoryStore()
	h := NewCapabilitiesHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/capabilities/lease_abc123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

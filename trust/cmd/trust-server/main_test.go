package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.trust/internal/receipt"
)

func TestHealthHandler(t *testing.T) {
	srv := NewServer("")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
}

func TestRegisterDomain(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"domain": "acme.com",
		"name":   "Acme Corp",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/domains", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusCreated, w.Body.String())
	}
}

func TestRegisterDomain_Duplicate(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"domain": "acme.com",
		"name":   "Acme Corp",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/domains", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	req2 := httptest.NewRequest(http.MethodPost, "/v1/domains", bytes.NewReader(b))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w2.Code, http.StatusConflict)
	}
}

func TestListDomains(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.AddOrganization("a.com", "Org A", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	orgs := resp["organizations"].([]interface{})
	if len(orgs) != 2 {
		t.Errorf("count = %d, want 2", len(orgs))
	}
}

func TestGetDomain(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("acme.com", "Acme Corp", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/domains/acme.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	org := resp["organization"].(map[string]interface{})
	if org["domain"] != "acme.com" {
		t.Errorf("domain = %v", org["domain"])
	}
}

func TestGetDomain_NotFound(t *testing.T) {
	srv := NewServer("")
	req := httptest.NewRequest(http.MethodGet, "/v1/domains/missing.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestRemoveDomain(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("acme.com", "Acme Corp", nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/domains/acme.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/domains/acme.com", nil)
	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d after removal", w2.Code, http.StatusNotFound)
	}
}

func TestCreateFederation(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)

	body := map[string]interface{}{
		"source":    "a.com",
		"target":    "b.com",
		"trust_level": 0.8,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/federations", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusCreated, w.Body.String())
	}
}

func TestRevokeFederation(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.Federate("a.com", "b.com", 0.8, nil)

	req := httptest.NewRequest(http.MethodDelete, "/v1/federations/a.com/b.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestListFederations(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.Federate("a.com", "b.com", 0.7, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/federations", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["node_count"].(float64)) != 2 {
		t.Errorf("node_count = %v, want 2", resp["node_count"])
	}
}

func TestComputePath(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.Federate("a.com", "b.com", 0.8, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/federations/path?source=a.com&target=b.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["direct"] != true {
		t.Errorf("direct = %v, want true", resp["direct"])
	}
	if resp["depth"].(float64) != 1 {
		t.Errorf("depth = %v, want 1", resp["depth"])
	}
}

func TestComputePath_NoPath(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/federations/path?source=a.com&target=b.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestRegisterFederatedIdentity(t *testing.T) {
	srv := NewServer("")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub

	body := map[string]interface{}{
		"identity_digest": hex.EncodeToString([]byte("agent-123")),
		"domain":          "acme.com",
		"signing_key":     hex.EncodeToString(priv),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/identities/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	var fid receipt.FederatedIdentity
	json.Unmarshal(w.Body.Bytes(), &fid)
	if len(fid.Signature) == 0 {
		t.Error("signature should be set")
	}
}

func TestVerifyFederatedIdentity(t *testing.T) {
	srv := NewServer("")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(24 * time.Hour)

	fid := &receipt.FederatedIdentity{
		IdentityDigest: hex.EncodeToString([]byte("agent-123")),
		Domain:         "acme.com",
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	}
	fid.Sign(priv)

	body := map[string]interface{}{
		"identity_digest": fid.IdentityDigest,
		"domain":         fid.Domain,
		"signature":      hex.EncodeToString(fid.Signature),
		"public_key":     hex.EncodeToString(pub),
		"issued_at":      issuedAt.Format(time.RFC3339),
		"expires_at":     expiresAt.Format(time.RFC3339),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/identities/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != true {
		t.Errorf("valid = %v, want true", resp["valid"])
	}
}

func TestVerifyFederatedIdentity_Expired(t *testing.T) {
	srv := NewServer("")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuedAt := time.Now().UTC().Add(-48 * time.Hour)
	expiresAt := issuedAt.Add(1 * time.Hour)

	fid := &receipt.FederatedIdentity{
		IdentityDigest: hex.EncodeToString([]byte("agent-123")),
		Domain:         "acme.com",
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	}
	fid.Sign(priv)

	body := map[string]interface{}{
		"identity_digest": fid.IdentityDigest,
		"domain":         fid.Domain,
		"signature":      hex.EncodeToString(fid.Signature),
		"public_key":     hex.EncodeToString(pub),
		"issued_at":      issuedAt.Format(time.RFC3339),
		"expires_at":     expiresAt.Format(time.RFC3339),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/identities/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["not_expired"] != false {
		t.Errorf("not_expired = %v, want false", resp["not_expired"])
	}
}

func TestVerifyCrossOrgReceipt(t *testing.T) {
	srv := NewServer("")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	timestamp := time.Now().UTC()

	crossOrgReceipt := &receipt.CrossOrgReceipt{
		ReceiptID:      "r-123",
		DecisionID:     "d-456",
		IssuingGateway: "gateway-a",
		IssuingOrg:     "acme.com",
		ActionType:     "access",
		Resource:       "/api/data",
		Decision:       "allow",
		AgentIdentity:  hex.EncodeToString([]byte("agent-789")),
		TrustScore:     0.95,
		Timestamp:      timestamp,
	}
	receipt.SignCrossOrgReceipt(crossOrgReceipt, priv)

	body := map[string]interface{}{
		"receipt_id":      crossOrgReceipt.ReceiptID,
		"decision_id":     crossOrgReceipt.DecisionID,
		"issuing_gateway": crossOrgReceipt.IssuingGateway,
		"issuing_org":    crossOrgReceipt.IssuingOrg,
		"action_type":    crossOrgReceipt.ActionType,
		"resource":       crossOrgReceipt.Resource,
		"decision":      crossOrgReceipt.Decision,
		"agent_identity": crossOrgReceipt.AgentIdentity,
		"trust_score":    crossOrgReceipt.TrustScore,
		"timestamp":      timestamp.Format(time.RFC3339),
		"signature":      hex.EncodeToString(crossOrgReceipt.Signature),
		"public_key":     hex.EncodeToString(pub),
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["valid"] != true {
		t.Errorf("valid = %v, want true", resp["valid"])
	}
}

func TestTrustStatus(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("acme.com", "Acme Corp", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.Federate("acme.com", "b.com", 0.9, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/trust-status/acme.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["federation_count"].(float64) != 1 {
		t.Errorf("federation_count = %v, want 1", resp["federation_count"])
	}
}

func TestGraphSnapshot(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)
	srv.graph.AddOrganization("b.com", "Org B", nil)
	srv.graph.Federate("a.com", "b.com", 0.7, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/graph", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["node_count"].(float64)) != 2 {
		t.Errorf("node_count = %v, want 2", resp["node_count"])
	}
}

func TestRegisterDomain_InvalidDomain(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"domain": "invalid domain with spaces",
		"name":   "Acme Corp",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/domains", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestComputePath_MissingParams(t *testing.T) {
	srv := NewServer("")
	req := httptest.NewRequest(http.MethodGet, "/v1/federations/path", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterFederatedIdentity_InvalidKey(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"identity_digest": hex.EncodeToString([]byte("agent-123")),
		"domain":         "acme.com",
		"signing_key":    "not-a-valid-key",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/identities/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestVerifyFederatedIdentity_InvalidPubKey(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"identity_digest": hex.EncodeToString([]byte("agent-123")),
		"domain":         "acme.com",
		"signature":      hex.EncodeToString(make([]byte, 64)),
		"public_key":     "invalid",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/identities/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestVerifyCrossOrgReceipt_InvalidPubKey(t *testing.T) {
	srv := NewServer("")
	body := map[string]interface{}{
		"receipt_id": "r-123",
		"signature":  hex.EncodeToString(make([]byte, 64)),
		"public_key": "invalid",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts/verify", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRevokeFederation_NotFound(t *testing.T) {
	srv := NewServer("")
	req := httptest.NewRequest(http.MethodDelete, "/v1/federations/a.com/b.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestRemoveDomain_NotFound(t *testing.T) {
	srv := NewServer("")
	req := httptest.NewRequest(http.MethodDelete, "/v1/domains/missing.com", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCreateFederation_SameOrg(t *testing.T) {
	srv := NewServer("")
	srv.graph.AddOrganization("a.com", "Org A", nil)

	body := map[string]interface{}{
		"source":     "a.com",
		"target":     "a.com",
		"trust_level": 0.8,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/federations", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
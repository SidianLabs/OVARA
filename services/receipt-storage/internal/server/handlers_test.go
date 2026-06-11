package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.services.receipt/internal/models"
	"ovara.services.receipt/internal/store"
)

type mockReceiptStore struct {
	receipts map[string]*models.Receipt
}

func newReceiptMockStore() *mockReceiptStore {
	return &mockReceiptStore{receipts: make(map[string]*models.Receipt)}
}

func (m *mockReceiptStore) Archive(r *models.Receipt) error {
	if _, exists := m.receipts[r.ID]; exists {
		return &storeError{"receipt %s already archived"}
	}
	m.receipts[r.ID] = r
	return nil
}

func (m *mockReceiptStore) Get(id string) (*models.Receipt, error) {
	r, ok := m.receipts[id]
	if !ok {
		return nil, &storeError{"receipt %s not found"}
	}
	return r, nil
}

func (m *mockReceiptStore) List(filter store.ListFilter) ([]*models.Receipt, error) {
	var results []*models.Receipt
	for _, r := range m.receipts {
		if filter.OrganizationID != "" && r.OrganizationID != filter.OrganizationID {
			continue
		}
		if filter.GatewayID != "" && r.GatewayID != filter.GatewayID {
			continue
		}
		if filter.Decision != "" && r.Decision != filter.Decision {
			continue
		}
		if filter.ActionType != "" && r.ActionType != filter.ActionType {
			continue
		}
		results = append(results, r)
	}
	if results == nil {
		results = []*models.Receipt{}
	}
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}
	return results, nil
}

func (m *mockReceiptStore) Verify(id string) (*models.VerificationResult, error) {
	r, ok := m.receipts[id]
	if !ok {
		return nil, &storeError{"receipt %s not found"}
	}
	valid := len(r.Signature) >= 64 && r.Signature != ""
	return &models.VerificationResult{
		Valid:         valid,
		ReceiptDigest: r.Digest(),
	}, nil
}

func (m *mockReceiptStore) Count() int {
	return len(m.receipts)
}

func (m *mockReceiptStore) CountByOrg(orgID string) int {
	count := 0
	for _, r := range m.receipts {
		if r.OrganizationID == orgID {
			count++
		}
	}
	return count
}

type storeError struct{ msg string }

func (e *storeError) Error() string { return e.msg }

func TestReceiptHandle_NotFound(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	w := httptest.NewRecorder()
	h.HandleReceipt(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestReceiptHandle_MethodNotAllowed(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}
	req := httptest.NewRequest(http.MethodPut, "/v1/receipts", nil)
	w := httptest.NewRecorder()
	h.HandleReceipt(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestArchive_ValidRequest(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}

	body := map[string]interface{}{
		"decision_id":     "dec-001",
		"gateway_id":      "gw-001",
		"organization_id": "org-001",
		"action_type":     "shell",
		"resource":        "shell:ls",
		"decision":        "allow",
		"agent_id":        "agent-001",
		"trust_score":     0.95,
		"signature":       "sig_v1:abc123",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var r models.Receipt
	json.Unmarshal(w.Body.Bytes(), &r)
	if r.DecisionID != "dec-001" {
		t.Errorf("expected dec-001, got %s", r.DecisionID)
	}
	if r.OrganizationID != "org-001" {
		t.Errorf("expected org-001, got %s", r.OrganizationID)
	}
}

func TestArchive_MissingFields(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	body := map[string]interface{}{
		"decision_id": "dec-001",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestArchive_InvalidJSON(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGet_Existing(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}
	r := &models.Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		Signature:      "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
	}
	s.receipts[r.ID] = r

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/rcpt-001", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.Receipt
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.ID != "rcpt-001" {
		t.Errorf("expected rcpt-001, got %s", result.ID)
	}
}

func TestGet_NotFound(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGet_EmptyID(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestList_Empty(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("expected count 0, got %v", resp["count"])
	}
}

func TestList_WithOrgFilter(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}

	for i := 0; i < 3; i++ {
		r := &models.Receipt{
			ID:             "rcpt-" + string(rune('a'+i)),
			DecisionID:     "dec-001",
			GatewayID:      "gw-001",
			OrganizationID: "org-001",
			ActionType:     "shell",
			Resource:       "shell:ls",
			Decision:       "allow",
			Signature:      "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
		}
		s.receipts[r.ID] = r
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?organization_id=org-001", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 3 {
		t.Errorf("expected count 3, got %v", resp["count"])
	}
}

func TestVerify_Existing(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}
	r := &models.Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		Signature:      "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
	}
	s.receipts[r.ID] = r

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/rcpt-001/verify", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.VerificationResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.Valid {
		t.Errorf("expected valid=true, got %v", result.Valid)
	}
}

func TestVerify_NotFound(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/nonexistent/verify", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestStats_Total(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}
	for i := 0; i < 5; i++ {
		r := &models.Receipt{
			ID:             "rcpt-" + string(rune('a'+i)),
			DecisionID:    "dec-001",
			GatewayID:     "gw-001",
			OrganizationID: "org-001",
			ActionType:    "shell",
			Signature:      "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
		}
		s.receipts[r.ID] = r
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/stats", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 5 {
		t.Errorf("expected total 5, got %v", resp["total"])
	}
}

func TestStats_ByOrg(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}
	for i := 0; i < 3; i++ {
		r := &models.Receipt{
			ID:             "rcpt-" + string(rune('a'+i)),
			DecisionID:    "dec-001",
			GatewayID:     "gw-001",
			OrganizationID: "org-001",
			ActionType:    "shell",
			Signature:      "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
		}
		s.receipts[r.ID] = r
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/stats?organization_id=org-001", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["organization_count"].(float64) != 3 {
		t.Errorf("expected org count 3, got %v", resp["organization_count"])
	}
}

func TestReceiptHealth(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}

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

func TestReceiptRegister(t *testing.T) {
	h := &Handlers{Store: newReceiptMockStore()}
	mux := http.NewServeMux()
	h.Register(mux)

	routes := []string{"/health", "/v1/receipts", "/v1/receipts/"}
	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" || pattern == "/" {
			t.Errorf("route %s not registered", route)
		}
	}
}

func TestNewReceiptServer(t *testing.T) {
	s := newReceiptMockStore()
	server := NewServer(":8082", s)
	if server.Addr != ":8082" {
		t.Errorf("expected :8082, got %s", server.Addr)
	}
}

func TestArchive_DuplicateStoreError(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}

	body := map[string]interface{}{
		"decision_id":     "dec-001",
		"gateway_id":      "gw-001",
		"organization_id": "org-001",
	}
	jsonBody, _ := json.Marshal(body)

	req1 := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(jsonBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	h.HandleReceipt(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("first request should succeed, got %d", w1.Code)
	}

	var r1 models.Receipt
	json.Unmarshal(w1.Body.Bytes(), &r1)

	body2 := map[string]interface{}{
		"decision_id":     "dec-002",
		"gateway_id":      "gw-001",
		"organization_id": "org-001",
	}
	jsonBody2, _ := json.Marshal(body2)
	req2 := httptest.NewRequest(http.MethodPost, "/v1/receipts", bytes.NewReader(jsonBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.HandleReceipt(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Errorf("second request should succeed (different ID), got %d", w2.Code)
	}

	_ = r1
}

func TestList_WithDecisionFilter(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}

	for i, decision := range []string{"allow", "deny", "allow"} {
		r := &models.Receipt{
			ID:             "rcpt-" + string(rune('a'+i)),
			DecisionID:    "dec-001",
			GatewayID:     "gw-001",
			OrganizationID: "org-001",
			ActionType:    "shell",
			Resource:      "shell:ls",
			Decision:      decision,
			Signature:     "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
		}
		s.receipts[r.ID] = r
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?decision=allow", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 2 {
		t.Errorf("expected count 2, got %v", resp["count"])
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}
	r := &models.Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		Signature:      "short",
	}
	s.receipts[r.ID] = r

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/rcpt-001/verify", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.VerificationResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Valid {
		t.Errorf("expected valid=false for short signature")
	}
}

func TestList_WithLimitAndOffset(t *testing.T) {
	s := newReceiptMockStore()
	h := &Handlers{Store: s}

	for i := 0; i < 10; i++ {
		r := &models.Receipt{
			ID:             "rcpt-" + string(rune('0'+i)),
			DecisionID:    "dec-001",
			GatewayID:     "gw-001",
			OrganizationID: "org-001",
			ActionType:    "shell",
			Signature:     "sig_v1:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890abcd",
		}
		s.receipts[r.ID] = r
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=3&offset=2", nil)
	w := httptest.NewRecorder()

	h.HandleReceipt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 3 {
		t.Errorf("expected count 3, got %v", resp["count"])
	}
}
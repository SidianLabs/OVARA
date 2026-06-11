package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.services.approval/internal/models"
	"ovara.services.approval/internal/store"
)

type mockStore struct {
	approvals map[string]*models.Approval
}

func newMockStore() *mockStore {
	return &mockStore{approvals: make(map[string]*models.Approval)}
}

func (m *mockStore) Create(a *models.Approval) error {
	if _, exists := m.approvals[a.ID]; exists {
		return &conflictError{a.ID}
	}
	m.approvals[a.ID] = a
	return nil
}

func (m *mockStore) Get(id string) (*models.Approval, error) {
	a, ok := m.approvals[id]
	if !ok {
		return nil, &notFoundError{id}
	}
	return a, nil
}

func (m *mockStore) List(filter store.ListFilter) ([]*models.Approval, error) {
	var results []*models.Approval
	for _, a := range m.approvals {
		if filter.State != "" && a.State != filter.State {
			continue
		}
		if filter.GatewayID != "" && a.GatewayID != filter.GatewayID {
			continue
		}
		if filter.AgentID != "" && a.AgentID != filter.AgentID {
			continue
		}
		results = append(results, a)
	}
	if results == nil {
		results = []*models.Approval{}
	}
	return results, nil
}

func (m *mockStore) Resolve(id string, state models.ApprovalState, resolvedBy string, reason string) error {
	a, ok := m.approvals[id]
	if !ok {
		return &notFoundError{id}
	}
	if a.State != models.StatePending {
		return &stateError{a.State}
	}
	now := time.Now().UTC()
	a.State = state
	a.ResolvedBy = resolvedBy
	a.Reason = reason
	a.ResolvedAt = &now
	return nil
}

func (m *mockStore) ExpireOlderThan(before time.Time) (int, error) {
	count := 0
	for id, a := range m.approvals {
		if a.State == models.StatePending && a.CreatedAt.Before(before) {
			a.State = models.StateExpired
			now := time.Now().UTC()
			a.ResolvedAt = &now
			a.Reason = "auto-expired"
			count++
			_ = id
		}
	}
	return count, nil
}

func (m *mockStore) Count() int { return len(m.approvals) }

type notFoundError struct{ id string }
type conflictError struct{ id string }
type stateError struct{ state models.ApprovalState }

func (e *notFoundError) Error() string   { return "approval " + e.id + " not found" }
func (e *conflictError) Error() string   { return "approval " + e.id + " already exists" }
func (e *stateError) Error() string      { return "approval is already " + string(e.state) }

func newHandlers(s store.Store) *Handlers {
	return &Handlers{Store: s}
}

func TestHandleApproval_RouteNotFound(t *testing.T) {
	h := newHandlers(newMockStore())
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	w := httptest.NewRecorder()
	h.HandleApproval(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleApproval_MethodNotAllowed(t *testing.T) {
	h := newHandlers(newMockStore())
	req := httptest.NewRequest(http.MethodPut, "/v1/approvals", nil)
	w := httptest.NewRecorder()
	h.HandleApproval(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCreate_ValidRequest(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)

	body := map[string]interface{}{
		"gateway_id":   "gw-001",
		"decision_id":  "dec-001",
		"action_type":  "shell",
		"resource":     "shell:ls",
		"agent_id":     "agent-001",
		"requested_by": "admin@example.com",
		"expires_in_seconds": 600,
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.create(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var a models.Approval
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if a.GatewayID != "gw-001" {
		t.Errorf("expected gateway_id gw-001, got %s", a.GatewayID)
	}
	if a.State != models.StatePending {
		t.Errorf("expected state pending, got %s", a.State)
	}
}

func TestCreate_MissingFields(t *testing.T) {
	h := newHandlers(newMockStore())

	body := map[string]interface{}{
		"gateway_id": "gw-001",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreate_InvalidJSON(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGet_Existing(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()
	a := &models.Approval{
		ID:          "apr-001",
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell",
		Resource:    "shell:ls",
		RequestedBy: "admin",
		State:       models.StatePending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
	s.approvals[a.ID] = a

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals/apr-001", nil)
	w := httptest.NewRecorder()

	h.get(w, req, "apr-001")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.Approval
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.ID != "apr-001" {
		t.Errorf("expected apr-001, got %s", result.ID)
	}
}

func TestGet_NotFound(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals/nonexistent", nil)
	w := httptest.NewRecorder()

	h.get(w, req, "nonexistent")

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGet_EmptyID(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals/", nil)
	w := httptest.NewRecorder()

	h.get(w, req, "")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestList_FilterByState(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		a := &models.Approval{
			ID:          "apr-" + string(rune('a'+i)),
			GatewayID:   "gw-001",
			DecisionID:  "dec-001",
			ActionType:  "shell",
			Resource:    "shell:ls",
			RequestedBy: "admin",
			State:       models.StatePending,
			CreatedAt:   now,
			ExpiresAt:   now.Add(10 * time.Minute),
		}
		s.approvals[a.ID] = a
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?state=pending", nil)
	w := httptest.NewRecorder()

	h.list(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["count"].(float64) != 3 {
		t.Errorf("expected count 3, got %v", resp["count"])
	}
}

func TestList_Empty(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
	w := httptest.NewRecorder()

	h.list(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("expected 0, got %v", resp["count"])
	}
}

func TestApprove_Valid(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()
	a := &models.Approval{
		ID:          "apr-001",
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell",
		Resource:    "shell:ls",
		RequestedBy: "admin",
		State:       models.StatePending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
	s.approvals[a.ID] = a

	body := map[string]interface{}{"resolved_by": "admin@example.com"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/apr-001/approve", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.approve(w, req, "apr-001")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result models.Approval
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.State != models.StateApproved {
		t.Errorf("expected approved, got %s", result.State)
	}
	if result.ResolvedBy != "admin@example.com" {
		t.Errorf("expected resolved_by admin@example.com, got %s", result.ResolvedBy)
	}
}

func TestApprove_NotFound(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/nonexistent/approve", nil)
	w := httptest.NewRecorder()

	h.approve(w, req, "nonexistent")

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeny_Valid(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()
	a := &models.Approval{
		ID:          "apr-001",
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell",
		Resource:    "shell:ls",
		RequestedBy: "admin",
		State:       models.StatePending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
	s.approvals[a.ID] = a

	body := map[string]interface{}{
		"reason":      "too risky",
		"resolved_by": "admin@example.com",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/apr-001/deny", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.deny(w, req, "apr-001")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result models.Approval
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.State != models.StateDenied {
		t.Errorf("expected denied, got %s", result.State)
	}
	if result.Reason != "too risky" {
		t.Errorf("expected reason 'too risky', got %s", result.Reason)
	}
}

func TestDeny_NotFound(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/nonexistent/deny", nil)
	w := httptest.NewRecorder()

	h.deny(w, req, "nonexistent")

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestExpire_BeforeRFC3339(t *testing.T) {
	h := newHandlers(newMockStore())

	body := map[string]interface{}{"before": "not-a-time"}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/expire", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.expire(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestStats(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		a := &models.Approval{
			ID:          "apr-" + string(rune('a'+i)),
			GatewayID:   "gw-001",
			DecisionID:  "dec-001",
			ActionType:  "shell",
			Resource:    "shell:ls",
			RequestedBy: "admin",
			State:       models.StatePending,
			CreatedAt:   now,
			ExpiresAt:   now.Add(10 * time.Minute),
		}
		s.approvals[a.ID] = a
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals/stats", nil)
	w := httptest.NewRecorder()

	h.stats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["total"].(float64) != 5 {
		t.Errorf("expected total 5, got %v", resp["total"])
	}
}

func TestHealth(t *testing.T) {
	h := newHandlers(newMockStore())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		path, prefix, want string
	}{
		{"/v1/approvals/apr-001/approve", "/v1/approvals/", "apr-001"},
		{"/v1/approvals/apr-001/deny", "/v1/approvals/", "apr-001"},
		{"/v1/approvals/apr-001", "/v1/approvals/", "apr-001"},
	}
	for _, tt := range tests {
		got := extractID(tt.path, tt.prefix)
		if got != tt.want {
			t.Errorf("extractID(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestWriteErr(t *testing.T) {
	w := httptest.NewRecorder()
	writeErr(w, http.StatusBadRequest, "test error")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "test error" {
		t.Errorf("expected error 'test error', got %s", resp["error"])
	}
}

func TestResolve_AlreadyResolved(t *testing.T) {
	s := newMockStore()
	h := newHandlers(s)
	now := time.Now().UTC()
	alreadyResolved := now.Add(-1 * time.Hour)
	a := &models.Approval{
		ID:          "apr-001",
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell",
		Resource:    "shell:ls",
		RequestedBy: "admin",
		State:       models.StateApproved,
		CreatedAt:   now.Add(-2 * time.Hour),
		ExpiresAt:   now.Add(10 * time.Minute),
		ResolvedAt:   &alreadyResolved,
	}
	s.approvals[a.ID] = a

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/apr-001/approve", nil)
	w := httptest.NewRecorder()

	h.approve(w, req, "apr-001")

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestRegister(t *testing.T) {
	h := newHandlers(newMockStore())
	mux := http.NewServeMux()
	h.Register(mux)

	routes := []string{"/health", "/v1/approvals", "/v1/approvals/"}
	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" || pattern == "/" {
			t.Errorf("route %s not registered", route)
		}
	}
}

func TestNewServer(t *testing.T) {
	s := newMockStore()
	server := NewServer(":8080", s)
	if server.Addr != ":8080" {
		t.Errorf("expected addr :8080, got %s", server.Addr)
	}
	if server.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", server.ReadTimeout)
	}
	if server.WriteTimeout != 10*time.Second {
		t.Errorf("expected write timeout 10s, got %v", server.WriteTimeout)
	}
}
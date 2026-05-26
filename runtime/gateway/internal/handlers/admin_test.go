package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type mockContinuationStore struct {
	nonTerminal []*continuation.Continuation
}

func (m *mockContinuationStore) Create(c *continuation.Continuation) error {
	return nil
}
func (m *mockContinuationStore) Get(id string) (*continuation.Continuation, bool) {
	return nil, false
}
func (m *mockContinuationStore) Update(c *continuation.Continuation) error {
	return nil
}
func (m *mockContinuationStore) ListByState(state continuation.State) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListByDecision(decisionID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListByAgent(agentID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListByApprovalID(approvalID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListAll() []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListNonTerminal() []*continuation.Continuation {
	return m.nonTerminal
}

func (m *mockContinuationStore) MarkExpired(id string) error {
	return nil
}

type mockExecutionStore struct {
	statsFunc func() (int, int, int, int, int)
}

func (m *mockExecutionStore) Create(e *execution.Execution) error {
	return nil
}
func (m *mockExecutionStore) Get(id string) (*execution.Execution, bool) {
	return nil, false
}
func (m *mockExecutionStore) Update(e *execution.Execution) error {
	return nil
}
func (m *mockExecutionStore) ListByContinuation(continuationID string) []*execution.Execution {
	return nil
}
func (m *mockExecutionStore) ListAll() []*execution.Execution {
	return nil
}
func (m *mockExecutionStore) ListByState(state execution.State) []*execution.Execution {
	return nil
}
func (m *mockExecutionStore) Stats() (int, int, int, int, int) {
	if m.statsFunc != nil {
		return m.statsFunc()
	}
	return 0, 0, 0, 0, 0
}

type mockEventStore struct{}

func (m *mockEventStore) Append(e *events.Event) {}
func (m *mockEventStore) List(limit int) []*events.Event { return nil }
func (m *mockEventStore) Get(id string) (*events.Event, bool) { return nil, false }
func (m *mockEventStore) Count() int { return 0 }

func TestAdminHandler_ReconcileContinuations(t *testing.T) {
	h := NewAdminHandler()
	h.SetContinuationStore(&mockContinuationStore{nonTerminal: nil})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile/continuations", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["action"] != "reconcile_continuations" {
		t.Errorf("expected action=reconcile_continuations, got %v", resp["action"])
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
}

func TestAdminHandler_ReconcileContinuations_WithExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)

	contStore := &mockContinuationStore{
		nonTerminal: []*continuation.Continuation{
			{
				ContinuationID: "cnt_1",
				State:          continuation.StateApproved,
				CreatedAt:      now.Add(-2 * time.Hour),
				ExpiresAt:      &past,
			},
		},
	}

	h := NewAdminHandler()
	h.SetContinuationStore(contStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile/continuations", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if int(resp["expired"].(float64)) != 1 {
		t.Errorf("expected expired=1, got %v", resp["expired"])
	}
}

func TestAdminHandler_ReconcileExecutions(t *testing.T) {
	execStore := &mockExecutionStore{
		statsFunc: func() (int, int, int, int, int) {
			return 10, 5, 2, 3, 0
		},
	}

	h := NewAdminHandler()
	h.SetExecutionStore(execStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/reconcile/executions", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["action"] != "reconcile_executions" {
		t.Errorf("expected action=reconcile_executions, got %v", resp["action"])
	}

	stats := resp["stats"].(map[string]any)
	if int(stats["total"].(float64)) != 10 {
		t.Errorf("expected total=10, got %v", stats["total"])
	}
	if int(stats["succeeded"].(float64)) != 5 {
		t.Errorf("expected succeeded=5, got %v", stats["succeeded"])
	}
	if int(stats["running"].(float64)) != 3 {
		t.Errorf("expected running=3, got %v", stats["running"])
	}
}

func TestAdminHandler_Compact_NotConfigured(t *testing.T) {
	h := NewAdminHandler()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/compact", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp["action"] != "compact" {
		t.Errorf("expected action=compact, got %v", resp["action"])
	}
}

func TestAdminHandler_SweepContinuations_NotFileBacked(t *testing.T) {
	h := NewAdminHandler()
	h.SetContinuationStore(&mockContinuationStore{})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/sweep/continuations", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminHandler_SweepEvents_NotFileBacked(t *testing.T) {
	h := NewAdminHandler()
	h.SetEventStore(&mockEventStore{})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/sweep/events", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminHandler_MethodNotAllowed(t *testing.T) {
	h := NewAdminHandler()

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	endpoints := []string{
		"/v1/admin/reconcile/continuations",
		"/v1/admin/reconcile/executions",
		"/v1/admin/compact",
		"/v1/admin/sweep/continuations",
		"/v1/admin/sweep/events",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405 for GET %s, got %d", ep, w.Code)
		}
	}
}

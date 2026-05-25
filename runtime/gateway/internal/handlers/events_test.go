package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/events"
)

func TestEventHandler_HandleList(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_1"))
	store.Append(events.NewEvent(events.EventTypeReceiptIssued).WithReceiptID("rcpt_1"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestEventHandler_HandleListWithLimit(t *testing.T) {
	store := events.NewInMemoryStore(100)
	for i := 0; i < 5; i++ {
		store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_" + string(rune('0'+i))))
	}

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?limit=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 3 {
		t.Errorf("count = %v, want 3", result["count"])
	}
}

func TestEventHandler_HandleListFilterByType(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_1"))
	store.Append(events.NewEvent(events.EventTypeReceiptIssued).WithReceiptID("rcpt_1"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_2"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?type=runtime.decision_evaluated", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestEventHandler_HandleGet(t *testing.T) {
	store := events.NewInMemoryStore(100)
	evt := events.NewEvent(events.EventTypeApprovalCreated).WithApprovalID("apr_test")
	store.Append(evt)

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events/"+evt.EventID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result events.Event
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result.ApprovalID != "apr_test" {
		t.Errorf("approval_id = %v, want apr_test", result.ApprovalID)
	}
}

func TestEventHandler_HandleGet_NotFound(t *testing.T) {
	store := events.NewInMemoryStore(100)
	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events/evt_nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestEventHandler_HandleList_MethodNotAllowed(t *testing.T) {
	store := events.NewInMemoryStore(100)
	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/events", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestEventHandler_HandleListFilterByAgentID(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_a").WithDecisionID("dec_1"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_b").WithDecisionID("dec_2"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_a").WithDecisionID("dec_3"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?agent_id=agt_a", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestEventHandler_HandleListFilterByDecisionID(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_target"))
	store.Append(events.NewEvent(events.EventTypeReceiptIssued).WithDecisionID("dec_target"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_other"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?decision_id=dec_target", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestEventHandler_HandleListFilterByApprovalID(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeApprovalCreated).WithApprovalID("apr_target"))
	store.Append(events.NewEvent(events.EventTypeApprovalResolved).WithApprovalID("apr_target"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithDecisionID("dec_other"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?approval_id=apr_target", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestEventHandler_HandleListMultipleFilters(t *testing.T) {
	store := events.NewInMemoryStore(100)
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_x").WithDecisionID("dec_1"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_x").WithDecisionID("dec_2"))
	store.Append(events.NewEvent(events.EventTypeDecisionEvaluated).WithAgentID("agt_y").WithDecisionID("dec_1"))

	h := NewEventHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/events?agent_id=agt_x&decision_id=dec_1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/continuation"
)

func TestContinuationHandler_HandleList(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c2 := continuation.NewContinuation("dec_2", "git.push", "git:acme/repo").WithAgentID("agt_b")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations", nil)
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

func TestContinuationHandler_HandleListFilterByState(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_2", "git.push", "git:acme/repo")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?state=approved", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleListFilterByAgent(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_x")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:ls").WithAgentID("agt_y")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?agent_id=agt_x", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleList_FilterByActionType(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_2", "exec", "exec:ls")
	c3 := continuation.NewContinuation("dec_3", "shell", "shell:pwd")
	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?action_type=shell", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestContinuationHandler_HandleList_FilterByEnvironment(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c1.Environment = "production"
	c2.Environment = "dev"
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?environment=production", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleList_FilterByApprovalID(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c1.ApprovalID = "apr_abc"
	c2.ApprovalID = "apr_xyz"
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?approval_id=apr_abc", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", result["count"])
	}
}

func TestContinuationHandler_HandleList_CompositeFilters(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_x")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_x")
	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami").WithAgentID("agt_y")
	c1.MarkApproved("admin")
	c2.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?state=approved&agent_id=agt_x", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestContinuationHandler_HandleList_EmptyResult(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?state=expired", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)
	if result["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0", result["count"])
	}
}

func TestContinuationHandler_HandleGet(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/"+c.ContinuationID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	cnt, ok := result["continuation"].(map[string]any)
	if !ok {
		t.Fatal("continuation not in response")
	}
	if cnt["state"] != string(continuation.StateApproved) {
		t.Errorf("state = %v, want approved", cnt["state"])
	}
}

func TestContinuationHandler_HandleGet_NotFound(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/cnt_nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestContinuationHandler_HandleEnqueue(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/enqueue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["state"] != string(continuation.StateQueued) {
		t.Errorf("state = %v, want queued", resp["state"])
	}

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != continuation.StateQueued {
		t.Errorf("continuation state = %v, want queued", updated.State)
	}
}

func TestContinuationHandler_HandleEnqueue_NotApproved(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/enqueue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleCancel(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.MarkApproved("admin")
	c.MarkQueued()
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["state"] != string(continuation.StateCancelled) {
		t.Errorf("state = %v, want cancelled", resp["state"])
	}

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != continuation.StateCancelled {
		t.Errorf("continuation state = %v, want cancelled", updated.State)
	}
}

func TestContinuationHandler_HandleCancel_NotCancellable(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestContinuationHandler_HandleQueue(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_2")
	c1.MarkApproved("admin")
	c1.MarkQueued()
	c2.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/queue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", resp["count"])
	}
}

func TestContinuationHandler_HandleQueue_MethodNotAllowed(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/queue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestContinuationHandler_HandleStats_IncludesQueued(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkQueued()
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["queued"].(float64) != 1 {
		t.Errorf("queued = %v, want 1", resp["queued"])
	}
}

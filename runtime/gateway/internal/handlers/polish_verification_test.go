package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/models"
)

func TestApprovalHandler_ErrorMessagesNotDoubleWrapped(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	t.Run("get nonexistent approval returns clean not-found message", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/approval/apr_nonexistent", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}

		var resp api.ErrorResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode JSON error: %v", err)
		}

		if resp.Error == "" {
			t.Error("error message should not be empty")
		}

		if containsDoubleWrapped(resp.Error) {
			t.Errorf("error message appears double-wrapped: %s", resp.Error)
		}
	})
}

func TestApprovalHandler_EmptyPendingListIsArrayNotNull(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/approval/pending", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0", result["count"])
	}

	approvals, ok := result["approvals"].([]any)
	if !ok {
		t.Errorf("approvals is not an array, got %T", result["approvals"])
	}
	if len(approvals) != 0 {
		t.Errorf("approvals length = %d, want 0", len(approvals))
	}
}

func TestApprovalHandler_ListApprovals(t *testing.T) {
	t.Run("list all approvals returns all items", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		req := &approval.CreateRequest{
			DecisionID:  "dec_1",
			ActionType:  models.ActionType("shell"),
			Resource:    "test-resource",
			Environment: models.Environment("local"),
		}
		if _, err := svc.CreateApproval(req); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}
		req.DecisionID = "dec_2"
		req.ActionType = models.ActionType("exec")
		req.Environment = models.Environment("dev")
		if _, err := svc.CreateApproval(req); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 2 {
			t.Errorf("count = %v, want 2", result["count"])
		}
	})

	t.Run("filter by status returns matching approvals", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_1",
			ActionType:  models.ActionType("shell"),
			Resource:    "test-resource",
			Environment: models.Environment("local"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?status=pending", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 1 {
			t.Errorf("count = %v, want 1", result["count"])
		}
	})

	t.Run("filter by requester returns matching approvals", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_unique",
			ActionType:  models.ActionType("shell"),
			Resource:    "test-resource",
			Environment: models.Environment("local"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}
		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_other",
			ActionType:  models.ActionType("exec"),
			Resource:    "test-resource",
			Environment: models.Environment("dev"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?requester=dec_unique", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 1 {
			t.Errorf("count = %v, want 1", result["count"])
		}
	})

	t.Run("filter by environment returns matching approvals", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_1",
			ActionType:  models.ActionType("shell"),
			Resource:    "test-resource",
			Environment: models.Environment("production"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}
		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_2",
			ActionType:  models.ActionType("exec"),
			Resource:    "test-resource",
			Environment: models.Environment("dev"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?environment=production", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 1 {
			t.Errorf("count = %v, want 1", result["count"])
		}
	})

	t.Run("filter by action_type returns matching approvals", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_1",
			ActionType:  models.ActionType("shell"),
			Resource:    "test-resource",
			Environment: models.Environment("local"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}
		if _, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_2",
			ActionType:  models.ActionType("exec"),
			Resource:    "test-resource",
			Environment: models.Environment("dev"),
		}); err != nil {
			t.Fatalf("failed to create approval: %v", err)
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?action_type=shell", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 1 {
			t.Errorf("count = %v, want 1", result["count"])
		}
	})

	t.Run("limit parameter caps results", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		for i, at := range []models.ActionType{"shell", "exec", "git.push"} {
			if _, err := svc.CreateApproval(&approval.CreateRequest{
				DecisionID:  "dec_" + string(rune('1'+i)),
				ActionType:  at,
				Resource:    "test-resource",
				Environment: models.Environment("local"),
			}); err != nil {
				t.Fatalf("failed to create approval: %v", err)
			}
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=2", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httpReq)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 2 {
			t.Errorf("count = %v, want 2", result["count"])
		}
	})

	t.Run("empty result returns empty array", func(t *testing.T) {
		store := approval.NewInMemoryStore()
		svc := approval.NewService(store)
		h := NewApprovalHandler(svc)
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)

		req := httptest.NewRequest(http.MethodGet, "/v1/approvals?status=approved", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if int(result["count"].(float64)) != 0 {
			t.Errorf("count = %v, want 0", result["count"])
		}

		approvals, ok := result["approvals"].([]any)
		if !ok {
			t.Errorf("approvals is not an array, got %T", result["approvals"])
		}
		if len(approvals) != 0 {
			t.Errorf("approvals length = %d, want 0", len(approvals))
		}
	})
}

func containsDoubleWrapped(msg string) bool {
	return len(msg) > 0 && (msg[:min(len(msg), 17)] == "approval not found" ||
		msg[:min(len(msg), 16)] == "receipt not found" ||
		msg[:min(len(msg), 16)] == "decision not found")
}

func TestApprovalHandler_ListApprovals_SortOldest(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	a1, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_new",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})
	a1.CreatedAt = now.Add(-1 * time.Hour)
	store.Update(a1)

	a2, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_old",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
	})
	a2.CreatedAt = now.Add(-3 * time.Hour)
	store.Update(a2)

	a3, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_middle",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:whoami",
		Environment: models.EnvironmentLocal,
	})
	a3.CreatedAt = now.Add(-2 * time.Hour)
	store.Update(a3)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 3 {
		t.Fatalf("len = %d, want 3", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_old" {
		t.Errorf("first item decision_id = %v, want dec_old (oldest)", first["decision_id"])
	}

	last := approvals[len(approvals)-1].(map[string]any)
	if last["decision_id"] != "dec_new" {
		t.Errorf("last item decision_id = %v, want dec_new (newest)", last["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_SortNewest(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	a1, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_new",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})
	a1.CreatedAt = now.Add(-1 * time.Hour)
	store.Update(a1)

	a2, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_old",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
	})
	a2.CreatedAt = now.Add(-3 * time.Hour)
	store.Update(a2)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?sort=newest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_new" {
		t.Errorf("first item decision_id = %v, want dec_new (newest)", first["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_SortWithFilter(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	a1, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_shell",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})
	a1.CreatedAt = now.Add(-1 * time.Hour)
	store.Update(a1)

	a2, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_exec",
		ActionType: models.ActionTypeExec,
		Resource:    "exec:ls",
		Environment: models.EnvironmentLocal,
	})
	a2.CreatedAt = now.Add(-2 * time.Hour)
	store.Update(a2)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?action_type=shell&sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 1 {
		t.Fatalf("len = %d, want 1", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_shell" {
		t.Errorf("decision_id = %v, want dec_shell", first["decision_id"])
	}
}

func TestContinuationHandler_HandleList_SortOldest(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	c1 := continuation.NewContinuation("dec_new", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-1 * time.Hour)
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_old", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-3 * time.Hour)
	c2.State = continuation.StateApproved
	c3 := continuation.NewContinuation("dec_middle", "shell", "shell:whoami")
	c3.CreatedAt = now.Add(-2 * time.Hour)
	c3.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 3 {
		t.Fatalf("len = %d, want 3", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_old" {
		t.Errorf("first item decision_id = %v, want dec_old (oldest)", first["decision_id"])
	}

	last := conts[len(conts)-1].(map[string]any)
	if last["decision_id"] != "dec_new" {
		t.Errorf("last item decision_id = %v, want dec_new (newest)", last["decision_id"])
	}
}

func TestContinuationHandler_HandleList_SortNewest(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	c1 := continuation.NewContinuation("dec_new", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-1 * time.Hour)
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_old", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-3 * time.Hour)
	c2.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?sort=newest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_new" {
		t.Errorf("first item decision_id = %v, want dec_new (newest)", first["decision_id"])
	}
}

func TestContinuationHandler_HandleList_SortWithRetryableFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	c1 := continuation.NewContinuation("dec_retryable", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-1 * time.Hour)
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	c1.RetryCount = 1
	c2 := continuation.NewContinuation("dec_not_retryable", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-2 * time.Hour)
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	c2.RetryCount = 3

	store.Create(c1)
	store.Create(c2)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?retryable=true&sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 1 {
		t.Fatalf("len = %d, want 1", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_retryable" {
		t.Errorf("decision_id = %v, want dec_retryable", first["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_CreatedBefore(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Minute)

	a1, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_old",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})
	a1.CreatedAt = now.Add(-2 * time.Hour)
	store.Update(a1)

	a2, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_new",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
	})
	a2.CreatedAt = now.Add(-30 * time.Minute)
	store.Update(a2)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?created_before="+cutoff.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 1 {
		t.Fatalf("len = %d, want 1", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_old" {
		t.Errorf("decision_id = %v, want dec_old", first["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_CreatedAfter(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Minute)

	a1, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_old",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})
	a1.CreatedAt = now.Add(-2 * time.Hour)
	store.Update(a1)

	a2, _ := svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_new",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
	})
	a2.CreatedAt = now.Add(-30 * time.Minute)
	store.Update(a2)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?created_after="+cutoff.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 1 {
		t.Fatalf("len = %d, want 1", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_new" {
		t.Errorf("decision_id = %v, want dec_new", first["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_CreatedBeforeInvalid(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_1",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
	})

	svc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_2",
		ActionType: models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
	})

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?created_before=invalid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 2 {
		t.Errorf("len = %d, want 2 (invalid value should be ignored)", len(approvals))
	}
}

func TestContinuationHandler_HandleList_CreatedBefore(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Minute)

	c1 := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-2 * time.Hour)
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_new", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-30 * time.Minute)
	c2.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?created_before="+cutoff.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 1 {
		t.Fatalf("len = %d, want 1", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_old" {
		t.Errorf("decision_id = %v, want dec_old", first["decision_id"])
	}
}

func TestContinuationHandler_HandleList_CreatedAfter(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Minute)

	c1 := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-2 * time.Hour)
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_new", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-30 * time.Minute)
	c2.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?created_after="+cutoff.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 1 {
		t.Fatalf("len = %d, want 1", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_new" {
		t.Errorf("decision_id = %v, want dec_new", first["decision_id"])
	}
}

func TestContinuationHandler_HandleList_CreatedBeforeWithSort(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	cutoff := now.Add(-30 * time.Minute)

	c1 := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-2 * time.Hour)
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_middle", "shell", "shell:whoami")
	c2.CreatedAt = now.Add(-1 * time.Hour)
	c2.State = continuation.StateApproved
	c3 := continuation.NewContinuation("dec_new", "shell", "shell:pwd")
	c3.CreatedAt = now.Add(-10 * time.Minute)
	c3.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?created_before="+cutoff.Format(time.RFC3339)+"&sort=newest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 2 {
		t.Fatalf("len = %d, want 2", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_middle" {
		t.Errorf("first item = %v, want dec_middle (newest within filter)", first["decision_id"])
	}
}

func TestContinuationHandler_HandleList_CreatedBeforeInvalid(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateApproved

	store.Create(c1)
	store.Create(c2)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?created_before=invalid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 2 {
		t.Errorf("len = %d, want 2 (invalid value should be ignored)", len(conts))
	}
}

func TestContinuationHandler_HandleList_LimitWithSortOldest(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		c.CreatedAt = now.Add(-time.Duration(i) * time.Hour)
		c.State = continuation.StateApproved
		store.Create(c)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?sort=oldest&limit=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 3 {
		t.Fatalf("len = %d, want 3", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_e" {
		t.Errorf("first item = %v, want dec_e (oldest)", first["decision_id"])
	}

	last := conts[len(conts)-1].(map[string]any)
	if last["decision_id"] != "dec_c" {
		t.Errorf("last item = %v, want dec_c (3rd oldest)", last["decision_id"])
	}
}

func TestContinuationHandler_HandleList_LimitWithSortNewest(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		c.CreatedAt = now.Add(-time.Duration(i) * time.Hour)
		c.State = continuation.StateApproved
		store.Create(c)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?sort=newest&limit=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	conts := result["continuations"].([]any)
	if len(conts) != 3 {
		t.Fatalf("len = %d, want 3", len(conts))
	}

	first := conts[0].(map[string]any)
	if first["decision_id"] != "dec_a" {
		t.Errorf("first item = %v, want dec_a (newest)", first["decision_id"])
	}

	last := conts[len(conts)-1].(map[string]any)
	if last["decision_id"] != "dec_c" {
		t.Errorf("last item = %v, want dec_c (3rd newest)", last["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_LimitWithSortOldest(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		a, _ := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType: models.ActionTypeShell,
			Resource:    "shell:ls",
			Environment: models.EnvironmentLocal,
		})
		a.CreatedAt = now.Add(-time.Duration(i) * time.Hour)
		store.Update(a)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?sort=oldest&limit=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 3 {
		t.Fatalf("len = %d, want 3", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_e" {
		t.Errorf("first item = %v, want dec_e (oldest)", first["decision_id"])
	}
}

func TestApprovalHandler_ListApprovals_LimitWithSortNewest(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		a, _ := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType: models.ActionTypeShell,
			Resource:    "shell:ls",
			Environment: models.EnvironmentLocal,
		})
		a.CreatedAt = now.Add(-time.Duration(i) * time.Hour)
		store.Update(a)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/approvals?sort=newest&limit=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	var result map[string]any
	json.NewDecoder(rec.Body).Decode(&result)

	approvals := result["approvals"].([]any)
	if len(approvals) != 3 {
		t.Fatalf("len = %d, want 3", len(approvals))
	}

	first := approvals[0].(map[string]any)
	if first["decision_id"] != "dec_a" {
		t.Errorf("first item = %v, want dec_a (newest)", first["decision_id"])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
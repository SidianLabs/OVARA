package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/approval"
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

func containsDoubleWrapped(msg string) bool {
	return len(msg) > 0 && (msg[:min(len(msg), 17)] == "approval not found" ||
		msg[:min(len(msg), 16)] == "receipt not found" ||
		msg[:min(len(msg), 16)] == "decision not found")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
)

func TestApprovalHandler_HandleListApprovals_CursorPagination_Basic(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		req := &approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType:  "shell",
			Resource:    "shell:ls",
			Environment: "test",
		}
		a := req.ToApproval("apr_" + string(rune('a'+i)))
		a.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(a)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", resp["count"])
	}

	nextCursor, ok := resp["next_cursor"].(string)
	if !ok || nextCursor == "" {
		t.Fatal("next_cursor should be present when limit is applied and more data exists")
	}

	approvals := resp["approvals"].([]any)
	id0 := approvals[0].(map[string]any)["approval_id"].(string)

	decoded, ok := decodeCursor(nextCursor)
	if !ok {
		t.Fatalf("next_cursor is not decodable: %s", nextCursor)
	}
	_ = decoded

	req2 := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=2&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	approvals2 := resp2["approvals"].([]any)
	for _, item := range approvals2 {
		m := item.(map[string]any)
		if m["approval_id"] == id0 {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestApprovalHandler_HandleListApprovals_CursorPagination_SortOldest(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		a := (&approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType:  "shell",
			Resource:    "shell:ls",
			Environment: "test",
		}).ToApproval("apr_" + string(rune('a'+i)))
		a.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(a)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=2&sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	approvals := resp["approvals"].([]any)
	firstID := approvals[0].(map[string]any)["approval_id"].(string)

	nextCursor, ok := resp["next_cursor"].(string)
	if !ok || nextCursor == "" {
		t.Fatal("next_cursor should be present")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=2&sort=oldest&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	approvals2 := resp2["approvals"].([]any)
	for _, item := range approvals2 {
		m := item.(map[string]any)
		if m["approval_id"] == firstID {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestApprovalHandler_HandleListApprovals_CursorPagination_InvalidCursor(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	a := (&approval.CreateRequest{
		DecisionID:  "dec_1",
		ActionType:  "shell",
		Resource:    "shell:ls",
		Environment: "test",
	}).ToApproval("apr_1")
	store.Create(a)

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=1&after=notavalidcursor", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	approvals := resp["approvals"].([]any)
	if len(approvals) != 1 {
		t.Errorf("count = %d, want 1 (invalid cursor ignored)", len(approvals))
	}
}

func TestApprovalHandler_HandleListApprovals_CursorPagination_EmptyResult(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	a1 := (&approval.CreateRequest{
		DecisionID:  "dec_a",
		ActionType:  "shell",
		Resource:    "shell:ls",
		Environment: "test",
	}).ToApproval("apr_a")
	a1.CreatedAt = now
	store.Create(a1)

	a2 := (&approval.CreateRequest{
		DecisionID:  "dec_b",
		ActionType:  "shell",
		Resource:    "shell:pwd",
		Environment: "test",
	}).ToApproval("apr_b")
	a2.CreatedAt = now.Add(-1 * time.Hour)
	store.Create(a2)

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	nextCursor := resp["next_cursor"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=1&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	approvals2 := resp2["approvals"].([]any)
	if len(approvals2) != 1 {
		t.Errorf("count = %d, want 1", len(approvals2))
	}

	a2Cursor := encodeCursor(Cursor{Timestamp: a2.CreatedAt, ID: a2.ApprovalID})
	req3 := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=1&after="+a2Cursor, nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var resp3 map[string]any
	json.NewDecoder(rec3.Body).Decode(&resp3)

	approvals3 := resp3["approvals"].([]any)
	if len(approvals3) != 0 {
		t.Errorf("count = %d, want 0 (cursor exhausted all items)", len(approvals3))
	}
}

func TestApprovalHandler_HandleListApprovals_CursorPagination_NoNextCursorWhenExhausted(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	for i := 0; i < 3; i++ {
		a := (&approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType:  "shell",
			Resource:    "shell:ls",
			Environment: "test",
		}).ToApproval("apr_" + string(rune('a'+i)))
		store.Create(a)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals?limit=100", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["next_cursor"]; ok {
		t.Error("next_cursor should not be present when all items fit in one page")
	}
}

func TestApprovalHandler_HandleListApprovals_MultiPageWalk(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	for i := 0; i < 7; i++ {
		a := (&approval.CreateRequest{
			DecisionID:  "dec_" + string(rune('a'+i)),
			ActionType:  "shell",
			Resource:    "shell:ls",
			Environment: "test",
		}).ToApproval("apr_" + string(rune('a'+i)))
		a.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(a)
	}

	seen := make(map[string]bool)
	page := 0
	nextCursor := ""

	for {
		url := "/v1/approvals?limit=3"
		if nextCursor != "" {
			url += "&after=" + nextCursor
		}

		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp map[string]any
		json.NewDecoder(rec.Body).Decode(&resp)

		approvals := resp["approvals"].([]any)
		for _, item := range approvals {
			m := item.(map[string]any)
			id := m["approval_id"].(string)
			if seen[id] {
				t.Errorf("page %d: approval_id %s already seen on previous page", page, id)
			}
			seen[id] = true
		}

		nextCursor, _ = resp["next_cursor"].(string)
		page++

		if nextCursor == "" {
			break
		}

		if page > 10 {
			t.Fatal("too many pages, possible infinite loop")
		}
	}

	if len(seen) != 7 {
		t.Errorf("total unique items seen = %d, want 7", len(seen))
	}
}
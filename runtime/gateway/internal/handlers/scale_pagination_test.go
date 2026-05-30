package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/approval"
)

func TestContinuationHandler_HandleList_LargeDataset_5000Items(t *testing.T) {
	store := continuation.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		c := continuation.NewContinuation("dec_scale_"+string(rune(i%26)+'a'), "shell", "shell:ls")
		c.CreatedAt = now.Add(-time.Duration(i) * time.Minute)
		c.State = continuation.StateQueued
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var allIDs []string
	pageCount := 0
	after := ""

	for {
		url := "/v1/continuations?limit=500"
		if after != "" {
			url += "&after=" + after
		}

		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp map[string]any
		json.NewDecoder(rec.Body).Decode(&resp)

		contns := resp["continuations"].([]any)
		pageCount++

		for _, item := range contns {
			m := item.(map[string]any)
			allIDs = append(allIDs, m["continuation_id"].(string))
		}

		nextCursor, ok := resp["next_cursor"].(string)
		if !ok || nextCursor == "" {
			break
		}
		after = nextCursor

		if pageCount > 20 {
			t.Fatal("too many pages, pagination may be broken")
		}
	}

	if len(allIDs) != 5000 {
		t.Errorf("total items collected = %d, want 5000", len(allIDs))
	}

	idSet := make(map[string]bool)
	for _, id := range allIDs {
		if idSet[id] {
			t.Errorf("duplicate id found: %s", id)
		}
		idSet[id] = true
	}
}

func TestExecutionHandler_HandleList_LargeDataset_5000Items(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		e := execution.NewExecution("cnt_exec_"+string(rune(i%26)+'a'), "dec_"+string(rune(i%26)+'a'), "apr_"+string(rune(i%26)+'a'), "agt_"+string(rune(i%26)+'a'), "shell", "shell:ls", 60)
		e.StartedAt = now.Add(-time.Duration(i) * time.Minute)
		store.Create(e)
	}

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var allIDs []string
	pageCount := 0
	after := ""

	for {
		url := "/v1/executions?limit=500"
		if after != "" {
			url += "&after=" + after
		}

		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp map[string]any
		json.NewDecoder(rec.Body).Decode(&resp)

		execs := resp["executions"].([]any)
		pageCount++

		for _, item := range execs {
			m := item.(map[string]any)
			allIDs = append(allIDs, m["execution_id"].(string))
		}

		nextCursor, ok := resp["next_cursor"].(string)
		if !ok || nextCursor == "" {
			break
		}
		after = nextCursor

		if pageCount > 20 {
			t.Fatal("too many pages, pagination may be broken")
		}
	}

	if len(allIDs) != 5000 {
		t.Errorf("total items collected = %d, want 5000", len(allIDs))
	}

	idSet := make(map[string]bool)
	for _, id := range allIDs {
		if idSet[id] {
			t.Errorf("duplicate id found: %s", id)
		}
		idSet[id] = true
	}
}

func TestApprovalHandler_HandleList_LargeDataset_5000Items(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)

	now := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		req := &approval.CreateRequest{
			DecisionID:  fmt.Sprintf("dec_ap_%d", i),
			ActionType:  "shell",
			Resource:    "shell:ls",
			Environment: "local",
		}
		a := req.ToApproval(fmt.Sprintf("apr_%d", i))
		a.CreatedAt = now.Add(-time.Duration(i) * time.Minute)
		if err := store.Create(a); err != nil {
			t.Fatalf("failed to create approval %d: %v", i, err)
		}
	}

	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var allIDs []string
	pageCount := 0
	after := ""

	for {
		url := "/v1/approvals?limit=500"
		if after != "" {
			url += "&after=" + after
		}

		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp map[string]any
		json.NewDecoder(rec.Body).Decode(&resp)

		approvals := resp["approvals"].([]any)
		pageCount++

		for _, item := range approvals {
			m := item.(map[string]any)
			allIDs = append(allIDs, m["approval_id"].(string))
		}

		nextCursor, ok := resp["next_cursor"].(string)
		if !ok || nextCursor == "" {
			break
		}
		after = nextCursor

		if pageCount > 20 {
			t.Fatal("too many pages, pagination may be broken")
		}
	}

	if len(allIDs) != 5000 {
		t.Errorf("total items collected = %d, want 5000", len(allIDs))
	}

	idSet := make(map[string]bool)
	for _, id := range allIDs {
		if idSet[id] {
			t.Errorf("duplicate id found: %s", id)
		}
		idSet[id] = true
	}
}

func TestContinuationHandler_HandleList_Pagination_NonOverlappingPages(t *testing.T) {
	store := continuation.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 150; i++ {
		c := continuation.NewContinuation("dec_page_"+string(rune(i%26)+'a'), "shell", "shell:ls")
		c.CreatedAt = now.Add(-time.Duration(i) * time.Minute)
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var allIDs []string
	var pageIDs [][]string
	after := ""

	for {
		url := "/v1/continuations?limit=50"
		if after != "" {
			url += "&after=" + after
		}

		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var resp map[string]any
		json.NewDecoder(rec.Body).Decode(&resp)

		contns := resp["continuations"].([]any)
		pageIDs = append(pageIDs, []string{})

		for _, item := range contns {
			m := item.(map[string]any)
			id := m["continuation_id"].(string)
			allIDs = append(allIDs, id)
			pageIDs[len(pageIDs)-1] = append(pageIDs[len(pageIDs)-1], id)
		}

		nextCursor, ok := resp["next_cursor"].(string)
		if !ok || nextCursor == "" {
			break
		}
		after = nextCursor
	}

	if len(allIDs) != 150 {
		t.Errorf("total items = %d, want 150", len(allIDs))
	}

	for i, page := range pageIDs {
		for j, id := range page {
			for k, otherPage := range pageIDs {
				if k == i {
					continue
				}
				for _, otherID := range otherPage {
					if id == otherID {
						t.Errorf("id %s appears on page %d pos %d and page %d - pages overlap", id, i, j, k)
					}
				}
			}
		}
	}
}
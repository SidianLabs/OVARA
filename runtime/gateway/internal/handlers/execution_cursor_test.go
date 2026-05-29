package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/execution"
)

func TestExecutionHandler_HandleList_CursorPagination_Basic(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		e := execution.NewExecution("cnt_"+string(rune('0'+i)), "dec_"+string(rune('a'+i)), "apr_"+string(rune('a'+i)), "agt_"+string(rune('a'+i)), "shell", "shell:ls", 60)
		e.StartedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(e)
	}

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=2", nil)
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

	c1 := resp["executions"].([]any)
	id0 := c1[0].(map[string]any)["execution_id"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=2&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	c2 := resp2["executions"].([]any)
	for _, item := range c2 {
		m := item.(map[string]any)
		if m["execution_id"] == id0 {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestExecutionHandler_HandleList_CursorPagination_SortOldest(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		e := execution.NewExecution("cnt_"+string(rune('0'+i)), "dec_"+string(rune('a'+i)), "apr_"+string(rune('a'+i)), "agt_"+string(rune('a'+i)), "shell", "shell:ls", 60)
		e.StartedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(e)
	}

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=2&sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	c1 := resp["executions"].([]any)
	firstID := c1[0].(map[string]any)["execution_id"].(string)

	nextCursor := resp["next_cursor"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=2&sort=oldest&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	c2 := resp2["executions"].([]any)
	for _, item := range c2 {
		m := item.(map[string]any)
		if m["execution_id"] == firstID {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestExecutionHandler_HandleList_CursorPagination_InvalidCursor(t *testing.T) {
	store := execution.NewInMemoryStore()

	e := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	store.Create(e)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=1&after=notavalidcursor", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	execs := resp["executions"].([]any)
	if len(execs) != 1 {
		t.Errorf("count = %d, want 1 (invalid cursor ignored)", len(execs))
	}
}

func TestExecutionHandler_HandleList_CursorPagination_EmptyResult(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	e1 := execution.NewExecution("cnt_a", "dec_a", "apr_a", "agt_a", "shell", "shell:ls", 60)
	e1.StartedAt = now
	store.Create(e1)

	e2 := execution.NewExecution("cnt_b", "dec_b", "apr_b", "agt_b", "shell", "shell:pwd", 60)
	e2.StartedAt = now.Add(-1 * time.Hour)
	store.Create(e2)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	nextCursor := resp["next_cursor"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=1&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	execs2 := resp2["executions"].([]any)
	if len(execs2) != 1 {
		t.Errorf("count = %d, want 1", len(execs2))
	}

	e2Cursor := encodeCursor(Cursor{Timestamp: e2.StartedAt, ID: e2.ExecutionID})
	req3 := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=1&after="+e2Cursor, nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var resp3 map[string]any
	json.NewDecoder(rec3.Body).Decode(&resp3)

	execs3 := resp3["executions"].([]any)
	if len(execs3) != 0 {
		t.Errorf("count = %d, want 0 (cursor exhausted all items)", len(execs3))
	}
}

func TestExecutionHandler_HandleList_CursorPagination_NoNextCursorWhenExhausted(t *testing.T) {
	store := execution.NewInMemoryStore()

	for i := 0; i < 3; i++ {
		e := execution.NewExecution("cnt_"+string(rune('a'+i)), "dec_"+string(rune('a'+i)), "apr_"+string(rune('a'+i)), "agt_"+string(rune('a'+i)), "shell", "shell:ls", 60)
		store.Create(e)
	}

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?limit=100", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["next_cursor"]; ok {
		t.Error("next_cursor should not be present when all items fit in one page")
	}
}

func TestExecutionHandler_HandleList_CursorWithFilters(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		e := execution.NewExecution("cnt_"+string(rune('a'+i)), "dec_"+string(rune('a'+i)), "apr_"+string(rune('a'+i)), "agt_"+string(rune('a'+i)), "shell", "shell:ls", 60)
		if i%2 == 0 {
			e.ActionType = "shell"
		} else {
			e.ActionType = "exec"
		}
		e.StartedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(e)
	}

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?action_type=shell&limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	execs := resp["executions"].([]any)
	if len(execs) != 2 {
		t.Errorf("count = %d, want 2", len(execs))
	}

	nextCursor := resp["next_cursor"].(string)

	req2 := httptest.NewRequest(http.MethodGet, "/v1/executions?action_type=shell&limit=2&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	execs2 := resp2["executions"].([]any)
	if len(execs2) != 1 {
		t.Errorf("page 2 count = %d, want 1", len(execs2))
	}
}

func TestExecutionHandler_HandleList_CursorWithStateFilter(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e1.StartedAt = now
	e1.MarkSucceeded(0, "ok", "")
	store.Create(e1)

	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:ls", 60)
	e2.StartedAt = now.Add(-1 * time.Hour)
	e2.MarkFailed("err", 1)
	store.Create(e2)

	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:ls", 60)
	e3.StartedAt = now.Add(-2 * time.Hour)
	e3.MarkTimedOut()
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?state=failed&limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	execs := resp["executions"].([]any)
	if len(execs) != 1 {
		t.Errorf("count = %d, want 1", len(execs))
	}

	// Only one failed execution exists, so no next_cursor should be present
	if _, ok := resp["next_cursor"]; ok {
		t.Error("next_cursor should not be present when only one item matches filter")
	}
}

func TestExecutionHandler_HandleList_CursorWithStateFilter_TwoPages(t *testing.T) {
	store := execution.NewInMemoryStore()

	now := time.Now().UTC()
	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e1.StartedAt = now
	e1.MarkFailed("err", 1)
	store.Create(e1)

	e2 := execution.NewExecution("cnt_2", "dec_2", "apr_2", "agt_2", "shell", "shell:ls", 60)
	e2.StartedAt = now.Add(-1 * time.Hour)
	e2.MarkFailed("err", 1)
	store.Create(e2)

	e3 := execution.NewExecution("cnt_3", "dec_3", "apr_3", "agt_3", "shell", "shell:ls", 60)
	e3.StartedAt = now.Add(-2 * time.Hour)
	e3.MarkTimedOut()
	store.Create(e3)

	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?state=failed&limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	execs := resp["executions"].([]any)
	if len(execs) != 1 {
		t.Errorf("count = %d, want 1", len(execs))
	}

	nextCursor, ok := resp["next_cursor"].(string)
	if !ok || nextCursor == "" {
		t.Fatal("next_cursor should be present when there are more items")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/executions?state=failed&limit=1&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	execs2 := resp2["executions"].([]any)
	if len(execs2) != 1 {
		t.Errorf("page 2 count = %d, want 1", len(execs2))
	}

	// Page 3 - cursor now at e2 (oldest failed), no more failed after e2
	e2Cursor := encodeCursor(Cursor{Timestamp: e2.StartedAt, ID: e2.ExecutionID})
	req3 := httptest.NewRequest(http.MethodGet, "/v1/executions?state=failed&limit=1&after="+e2Cursor, nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var resp3 map[string]any
	json.NewDecoder(rec3.Body).Decode(&resp3)

	execs3 := resp3["executions"].([]any)
	if len(execs3) != 0 {
		t.Errorf("count = %d, want 0 (cursor exhausted)", len(execs3))
	}
}
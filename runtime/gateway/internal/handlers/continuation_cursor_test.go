package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/continuation"
)

func TestContinuationHandler_HandleList_CursorPagination_Basic(t *testing.T) {
	store := continuation.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		c.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=2", nil)
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

	c1, ok := resp["continuations"].([]any)
	if !ok {
		t.Fatalf("continuations not a slice")
	}
	id0 := c1[0].(map[string]any)["continuation_id"].(string)

	decoded, ok := decodeCursor(nextCursor)
	if !ok {
		t.Fatalf("next_cursor is not decodable: %s", nextCursor)
	}
	_ = decoded // decoded timestamp used implicitly via ordering assertion below

	req2 := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=2&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	c2, ok := resp2["continuations"].([]any)
	if !ok {
		t.Fatalf("continuations not a slice on page 2")
	}

	// Item from page 1 should not appear on page 2
	for _, item := range c2 {
		m := item.(map[string]any)
		if m["continuation_id"] == id0 {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestContinuationHandler_HandleList_CursorPagination_SortOldest(t *testing.T) {
	store := continuation.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		c.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=2&sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	c1 := resp["continuations"].([]any)
	// With sort=oldest, first item should be the oldest
	firstID := c1[0].(map[string]any)["continuation_id"].(string)

	nextCursor, ok := resp["next_cursor"].(string)
	if !ok || nextCursor == "" {
		t.Fatal("next_cursor should be present")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=2&sort=oldest&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	c2 := resp2["continuations"].([]any)
	for _, item := range c2 {
		m := item.(map[string]any)
		if m["continuation_id"] == firstID {
			t.Error("first item from page 1 should not appear on page 2")
		}
	}
}

func TestContinuationHandler_HandleList_CursorPagination_InvalidCursor(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	store.Create(c)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=1&after=notavalidcursor", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	// Invalid cursor should be silently ignored (no filtering applied)
	contns := resp["continuations"].([]any)
	if len(contns) != 1 {
		t.Errorf("count = %d, want 1 (invalid cursor ignored)", len(contns))
	}
}

func TestContinuationHandler_HandleList_CursorPagination_EmptyResult(t *testing.T) {
	store := continuation.NewInMemoryStore()

	// Create 2 items, then use a cursor that points to item 1 so item 2 is all that remains
	now := time.Now().UTC()
	c1 := continuation.NewContinuation("dec_a", "shell", "shell:ls")
	c1.CreatedAt = now
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_b", "shell", "shell:pwd")
	c2.CreatedAt = now.Add(-1 * time.Hour)
	store.Create(c2)

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// First page
	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	nextCursor := resp["next_cursor"].(string)

	// Second page with the cursor pointing at c1 (the item returned in page 1)
	// In descending order (newest first), c2 is older than c1, so c2 should appear
	req2 := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=1&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	contns := resp2["continuations"].([]any)
	if len(contns) != 1 {
		t.Errorf("count = %d, want 1", len(contns))
	}

	// Third page - cursor is now at c2 (the oldest). No items are older than c2,
	// so in descending order nothing remains after c2
	c2Cursor := encodeCursor(Cursor{Timestamp: c2.CreatedAt, ID: c2.ContinuationID})
	req3 := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=1&after="+c2Cursor, nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	var resp3 map[string]any
	json.NewDecoder(rec3.Body).Decode(&resp3)

	contns3 := resp3["continuations"].([]any)
	if len(contns3) != 0 {
		t.Errorf("count = %d, want 0 (cursor exhausted all items)", len(contns3))
	}
}

func TestContinuationHandler_HandleList_CursorPagination_NoNextCursorWhenExhausted(t *testing.T) {
	store := continuation.NewInMemoryStore()

	for i := 0; i < 3; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=100", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["next_cursor"]; ok {
		t.Error("next_cursor should not be present when all items fit in one page")
	}
}

func TestEncodeDecodeCursor_RoundTrip(t *testing.T) {
	orig := Cursor{
		Timestamp: time.Now().UTC(),
		ID:        "cnt_abc123",
	}

	encoded := encodeCursor(orig)
	decoded, ok := decodeCursor(encoded)

	if !ok {
		t.Fatalf("decodeCursor returned false for valid encoded cursor: %s", encoded)
	}
	if !decoded.Timestamp.Equal(orig.Timestamp) {
		t.Errorf("timestamp mismatch: got %v, want %v", decoded.Timestamp, orig.Timestamp)
	}
	if decoded.ID != orig.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, orig.ID)
	}
}

func TestDecodeCursor_InvalidStrings(t *testing.T) {
	invalid := []string{"", "notbase64!", "SGVsbG8=", "invalid", "Zm9vOmJhcg=="}
	for _, s := range invalid {
		if _, ok := decodeCursor(s); ok {
			t.Errorf("decodeCursor(%q) returned true, want false", s)
		}
	}
}

func TestContinuationHandler_HandleList_CursorWithFilters(t *testing.T) {
	store := continuation.NewInMemoryStore()

	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		if i%2 == 0 {
			c.ActionType = "shell"
		} else {
			c.ActionType = "exec"
		}
		c.CreatedAt = now.Add(time.Duration(i) * time.Hour)
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations?action_type=shell&limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	contns := resp["continuations"].([]any)
	if len(contns) != 2 {
		t.Errorf("count = %d, want 2", len(contns))
	}

	nextCursor, _ := resp["next_cursor"].(string)
	if nextCursor == "" {
		t.Fatal("next_cursor should be present")
	}

	// Use cursor with same filter
	req2 := httptest.NewRequest(http.MethodGet, "/v1/continuations?action_type=shell&limit=2&after="+nextCursor, nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)

	contns2 := resp2["continuations"].([]any)
	// Should have 1 more shell item (3rd shell item)
	if len(contns2) != 1 {
		t.Errorf("page 2 count = %d, want 1", len(contns2))
	}
}
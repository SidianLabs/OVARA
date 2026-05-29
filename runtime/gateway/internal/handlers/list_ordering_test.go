package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/models"
)

// These tests lock in the deterministic ordering contract for the operator
// list endpoints. Before this work the endpoints returned items in Go
// map-iteration order, so `limit` returned a random subset. The contract is:
//   - default order is newest-first (by created/started timestamp)
//   - sort=oldest reverses to oldest-first
//   - limit returns the first N of the sorted slice
//   - ties are broken by ID so results are fully reproducible

func decodeList(t *testing.T, rec *httptest.ResponseRecorder, key string) []map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	raw, ok := result[key].([]any)
	if !ok {
		t.Fatalf("response missing %q array: %v", key, result)
	}
	items := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		items = append(items, r.(map[string]any))
	}
	return items
}

func TestContinuationHandler_HandleList_DefaultOrderNewestFirst(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	c1 := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c1.CreatedAt = now.Add(-3 * time.Hour)
	c2 := continuation.NewContinuation("dec_mid", "shell", "shell:ls")
	c2.CreatedAt = now.Add(-2 * time.Hour)
	c3 := continuation.NewContinuation("dec_new", "shell", "shell:ls")
	c3.CreatedAt = now.Add(-1 * time.Hour)
	// Insert out of order so map iteration cannot accidentally match.
	store.Create(c2)
	store.Create(c3)
	store.Create(c1)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "continuations")
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	wantOrder := []string{"dec_new", "dec_mid", "dec_old"}
	for i, want := range wantOrder {
		if items[i]["decision_id"] != want {
			t.Errorf("item[%d].decision_id = %v, want %v (newest first default)", i, items[i]["decision_id"], want)
		}
	}
}

func TestContinuationHandler_HandleList_LimitReturnsNewestDeterministically(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls")
		c.CreatedAt = now.Add(time.Duration(i) * time.Minute) // dec_a oldest .. dec_j newest
		store.Create(c)
	}

	// Run twice to prove the default+limit result is stable, not random.
	var firstRun []string
	for run := 0; run < 2; run++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/continuations?limit=3", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		items := decodeList(t, rec, "continuations")
		if len(items) != 3 {
			t.Fatalf("run %d: len = %d, want 3", run, len(items))
		}
		got := []string{
			items[0]["decision_id"].(string),
			items[1]["decision_id"].(string),
			items[2]["decision_id"].(string),
		}
		want := []string{"dec_j", "dec_i", "dec_h"}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("run %d: item[%d] = %s, want %s (newest 3)", run, i, got[i], want[i])
			}
		}
		if run == 0 {
			firstRun = got
		} else if got[0] != firstRun[0] || got[1] != firstRun[1] || got[2] != firstRun[2] {
			t.Errorf("limit result not stable across runs: %v vs %v", firstRun, got)
		}
	}
}

func TestApprovalHandler_ListApprovals_DefaultOrderNewestFirst(t *testing.T) {
	store := approval.NewInMemoryStore()
	svc := approval.NewService(store)
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	mk := func(dec string, age time.Duration) {
		a, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID:  dec,
			ActionType:  models.ActionType("shell"),
			Resource:    "shell:ls",
			Environment: models.Environment("local"),
		})
		if err != nil {
			t.Fatalf("create approval: %v", err)
		}
		a.CreatedAt = now.Add(-age)
		if err := store.Update(a); err != nil {
			t.Fatalf("update approval: %v", err)
		}
	}
	mk("dec_old", 3*time.Hour)
	mk("dec_new", 1*time.Hour)
	mk("dec_mid", 2*time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "approvals")
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	wantOrder := []string{"dec_new", "dec_mid", "dec_old"}
	for i, want := range wantOrder {
		if items[i]["decision_id"] != want {
			t.Errorf("item[%d].decision_id = %v, want %v (newest first default)", i, items[i]["decision_id"], want)
		}
	}
}

func TestExecutionHandler_ListExecutions_DefaultOrderNewestFirst(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	base := time.Now().UTC()
	mk := func(cnt string, startOffset time.Duration) {
		e := execution.NewExecution(cnt, "dec_"+cnt, "apr", "agt", "shell", "shell:ls", 60)
		e.MarkSucceeded(0, "", "")
		e.StartedAt = base.Add(startOffset)
		store.Create(e)
	}
	mk("cnt_old", -3*time.Hour)
	mk("cnt_new", -1*time.Hour)
	mk("cnt_mid", -2*time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "executions")
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	wantOrder := []string{"cnt_new", "cnt_mid", "cnt_old"}
	for i, want := range wantOrder {
		if items[i]["continuation_id"] != want {
			t.Errorf("item[%d].continuation_id = %v, want %v (newest first default)", i, items[i]["continuation_id"], want)
		}
	}
}

func TestExecutionHandler_ListExecutions_SortOldest(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	base := time.Now().UTC()
	mk := func(cnt string, startOffset time.Duration) {
		e := execution.NewExecution(cnt, "dec_"+cnt, "apr", "agt", "shell", "shell:ls", 60)
		e.MarkSucceeded(0, "", "")
		e.StartedAt = base.Add(startOffset)
		store.Create(e)
	}
	mk("cnt_old", -3*time.Hour)
	mk("cnt_new", -1*time.Hour)
	mk("cnt_mid", -2*time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?sort=oldest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "executions")
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	wantOrder := []string{"cnt_old", "cnt_mid", "cnt_new"}
	for i, want := range wantOrder {
		if items[i]["continuation_id"] != want {
			t.Errorf("item[%d].continuation_id = %v, want %v (oldest first)", i, items[i]["continuation_id"], want)
		}
	}
}

func TestExecutionHandler_ListExecutions_SortNewestWithLimit(t *testing.T) {
	store := execution.NewInMemoryStore()
	h := NewExecutionHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	base := time.Now().UTC()
	for i := 0; i < 6; i++ {
		e := execution.NewExecution("cnt_"+string(rune('a'+i)), "dec", "apr", "agt", "shell", "shell:ls", 60)
		e.MarkSucceeded(0, "", "")
		e.StartedAt = base.Add(time.Duration(i) * time.Minute) // cnt_a oldest .. cnt_f newest
		store.Create(e)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/executions?sort=newest&limit=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "executions")
	if len(items) != 2 {
		t.Fatalf("len = %d, want 2", len(items))
	}
	if items[0]["continuation_id"] != "cnt_f" || items[1]["continuation_id"] != "cnt_e" {
		t.Errorf("got [%v %v], want [cnt_f cnt_e] (newest 2)",
			items[0]["continuation_id"], items[1]["continuation_id"])
	}
}

func TestParseLimit_DefaultsAndCaps(t *testing.T) {
	mk := func(raw string) *http.Request {
		url := "/x"
		if raw != "" {
			url += "?limit=" + raw
		}
		return httptest.NewRequest(http.MethodGet, url, nil)
	}

	cases := []struct {
		raw  string
		want int
	}{
		{"", defaultListLimit},
		{"0", defaultListLimit},
		{"-5", defaultListLimit},
		{"abc", defaultListLimit},
		{"50", 50},
		{"1000", 1000},
		{"5000", maxListLimit},
	}
	for _, tc := range cases {
		if got := parseLimit(mk(tc.raw), defaultListLimit, maxListLimit); got != tc.want {
			t.Errorf("parseLimit(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestContinuationHandler_HandleQueue_FIFOOrder(t *testing.T) {
	store := continuation.NewInMemoryStore()
	h := NewContinuationHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	now := time.Now().UTC()
	mk := func(dec string, queuedOffset time.Duration) {
		c := continuation.NewContinuation(dec, "shell", "shell:ls")
		c.State = continuation.StateQueued
		qa := now.Add(queuedOffset)
		c.QueuedAt = &qa
		store.Create(c)
	}
	mk("dec_first", -3*time.Minute)
	mk("dec_third", -1*time.Minute)
	mk("dec_second", -2*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/v1/continuations/queue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	items := decodeList(t, rec, "queue")
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	wantOrder := []string{"dec_first", "dec_second", "dec_third"}
	for i, want := range wantOrder {
		if items[i]["decision_id"] != want {
			t.Errorf("queue item[%d].decision_id = %v, want %v (FIFO oldest queued first)", i, items[i]["decision_id"], want)
		}
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
)

func TestBulkRetry_DryRun_NoChanges(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?dry_run=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 2 {
		t.Errorf("matched = %d, want 2", resp.Matched)
	}
	if resp.Acted != 2 {
		t.Errorf("acted = %d, want 2", resp.Acted)
	}
	if resp.Skipped != 0 {
		t.Errorf("skipped = %d, want 0", resp.Skipped)
	}
	if !resp.DryRun {
		t.Error("dry_run should be true")
	}

	for _, c := range []string{c1.ContinuationID, c2.ContinuationID} {
		updated, _ := store.Get(c)
		if updated.State != continuation.StateExecuted {
			t.Errorf("continuation %s state = %v, want executed (dry run)", c, updated.State)
		}
	}
}

func TestBulkRetry_ExecutesWithConfirm(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Acted != 2 {
		t.Errorf("acted = %d, want 2", resp.Acted)
	}
	if resp.DryRun {
		t.Error("dry_run should be false")
	}

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.State != continuation.StateResumed {
		t.Errorf("c1 state = %v, want resumed", updated1.State)
	}
	if updated1.RetryCount != 1 {
		t.Errorf("c1 retry_count = %d, want 1", updated1.RetryCount)
	}

	updated2, _ := store.Get(c2.ContinuationID)
	if updated2.State != continuation.StateResumed {
		t.Errorf("c2 state = %v, want resumed", updated2.State)
	}
}

func TestBulkRetry_CapExceeded_RequiresConfirm(t *testing.T) {
	store := continuation.NewInMemoryStore()
	for i := 0; i < 30; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls").WithAgentID("agt_1")
		c.State = continuation.StateExecuted
		c.MaxRetries = 3
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var errResp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errResp["error"] != "batch size exceeds cap" {
		t.Errorf("error = %v, want 'batch size exceeds cap'", errResp["error"])
	}
}

func TestBulkRetry_CapExceededWithConfirm(t *testing.T) {
	store := continuation.NewInMemoryStore()
	for i := 0; i < 30; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls").WithAgentID("agt_1")
		c.State = continuation.StateExecuted
		c.MaxRetries = 3
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Acted != 30 {
		t.Errorf("acted = %d, want 30", resp.Acted)
	}
}

func TestBulkRetry_MixedState_SkipsNonRetryable(t *testing.T) {
	store := continuation.NewInMemoryStore()

	cExecuted := continuation.NewContinuation("dec_ex", "shell", "shell:ls").WithAgentID("agt_1")
	cExecuted.State = continuation.StateExecuted
	cExecuted.MaxRetries = 3
	store.Create(cExecuted)

	cQueued := continuation.NewContinuation("dec_q", "shell", "shell:pwd").WithAgentID("agt_1")
	cQueued.State = continuation.StateQueued
	store.Create(cQueued)

	cDenied := continuation.NewContinuation("dec_d", "shell", "shell:whoami").WithAgentID("agt_1")
	cDenied.State = continuation.StateDenied
	store.Create(cDenied)

	cResumed := continuation.NewContinuation("dec_r", "shell", "shell:id").WithAgentID("agt_1")
	cResumed.State = continuation.StateResumed
	cResumed.MaxRetries = 3
	store.Create(cResumed)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 4 {
		t.Errorf("matched = %d, want 4", resp.Matched)
	}
	if resp.Acted != 2 {
		t.Errorf("acted = %d, want 2 (executed+resumed)", resp.Acted)
	}
	if resp.Skipped != 2 {
		t.Errorf("skipped = %d, want 2 (queued+denied)", resp.Skipped)
	}
	if len(resp.SkippedItems) != 2 {
		t.Errorf("skipped_items count = %d, want 2", len(resp.SkippedItems))
	}

	updatedQueued, _ := store.Get(cQueued.ContinuationID)
	if updatedQueued.State != continuation.StateQueued {
		t.Errorf("queued was acted on: state = %v", updatedQueued.State)
	}

	updatedDenied, _ := store.Get(cDenied.ContinuationID)
	if updatedDenied.State != continuation.StateDenied {
		t.Errorf("denied was acted on: state = %v", updatedDenied.State)
	}
}

func TestBulkRetry_Idempotent(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateResumed
	c2.MaxRetries = 2
	c2.RetryCount = 1
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("first call: status = %d, want 200", rec.Code)
	}

	var resp1 bulkRetryResponse
	json.NewDecoder(rec.Body).Decode(&resp1)
	if resp1.Acted != 2 {
		t.Errorf("first call: acted = %d, want 2", resp1.Acted)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 bulkRetryResponse
	json.NewDecoder(rec2.Body).Decode(&resp2)
	if resp2.Acted != 1 {
		t.Errorf("second call: acted = %d, want 1 (c2 exhausted, c1 still retryable)", resp2.Acted)
	}
	if resp2.Skipped != 1 {
		t.Errorf("second call: skipped = %d, want 1", resp2.Skipped)
	}

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.RetryCount != 2 {
		t.Errorf("c1 retry_count = %d, want 2", updated1.RetryCount)
	}

	updated2, _ := store.Get(c2.ContinuationID)
	if updated2.RetryCount != 2 {
		t.Errorf("c2 retry_count = %d, want 2 (not double-applied)", updated2.RetryCount)
	}
}

func TestBulkRetry_EmptyMatch(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateApproved
	store.Create(c)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?state=nonexistent&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 0 {
		t.Errorf("matched = %d, want 0", resp.Matched)
	}
	if resp.Acted != 0 {
		t.Errorf("acted = %d, want 0", resp.Acted)
	}
}

func TestBulkRetry_StateFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_ex", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_re", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateResumed
	c2.MaxRetries = 3
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_qu", "shell", "shell:id").WithAgentID("agt_1")
	c3.State = continuation.StateQueued
	store.Create(c3)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?state=executed&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 1 {
		t.Errorf("matched = %d, want 1", resp.Matched)
	}
	if resp.Acted != 1 {
		t.Errorf("acted = %d, want 1", resp.Acted)
	}
}

func TestBulkRetry_RetryableFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_ex", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_max", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 1
	c2.RetryCount = 1
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_qu", "shell", "shell:id").WithAgentID("agt_1")
	c3.State = continuation.StateQueued
	store.Create(c3)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?retryable=true&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 1 {
		t.Errorf("matched (retryable) = %d, want 1", resp.Matched)
	}
	if resp.Acted != 1 {
		t.Errorf("acted = %d, want 1", resp.Acted)
	}
}

func TestBulkRetry_CreatedBeforeFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	old := continuation.NewContinuation("dec_old", "shell", "shell:ls").WithAgentID("agt_1")
	old.State = continuation.StateExecuted
	old.MaxRetries = 3
	store.Create(old)

	new := continuation.NewContinuation("dec_new", "shell", "shell:pwd").WithAgentID("agt_1")
	new.State = continuation.StateExecuted
	new.MaxRetries = 3
	store.Create(new)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	cutoff := new.CreatedAt.Add(1 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?created_before="+cutoff+"&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 2 {
		t.Errorf("matched = %d, want 2", resp.Matched)
	}
}

func TestBulkRetry_AuditEvents(t *testing.T) {
	store := continuation.NewInMemoryStore()
	eventStore := events.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if eventStore.Count() < 3 {
		t.Errorf("event count = %d, want >= 3 (2 item events + 1 batch event)", eventStore.Count())
	}
}

func TestBulkCancel_DryRun_NoChanges(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateReady
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?dry_run=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 2 {
		t.Errorf("matched = %d, want 2", resp.Matched)
	}
	if resp.Acted != 2 {
		t.Errorf("acted = %d, want 2", resp.Acted)
	}
	if !resp.DryRun {
		t.Error("dry_run should be true")
	}

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.State != continuation.StateQueued {
		t.Errorf("c1 state = %v, want queued (dry run)", updated1.State)
	}

	updated2, _ := store.Get(c2.ContinuationID)
	if updated2.State != continuation.StateReady {
		t.Errorf("c2 state = %v, want ready (dry run)", updated2.State)
	}
}

func TestBulkCancel_ExecutesWithConfirm(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateResumed
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Acted != 2 {
		t.Errorf("acted = %d, want 2", resp.Acted)
	}

	updated1, _ := store.Get(c1.ContinuationID)
	if updated1.State != continuation.StateCancelled {
		t.Errorf("c1 state = %v, want cancelled", updated1.State)
	}

	updated2, _ := store.Get(c2.ContinuationID)
	if updated2.State != continuation.StateCancelled {
		t.Errorf("c2 state = %v, want cancelled", updated2.State)
	}
}

func TestBulkCancel_CapExceeded_RequiresConfirm(t *testing.T) {
	store := continuation.NewInMemoryStore()
	for i := 0; i < 30; i++ {
		c := continuation.NewContinuation("dec_"+string(rune('a'+i)), "shell", "shell:ls").WithAgentID("agt_1")
		c.State = continuation.StateQueued
		store.Create(c)
	}

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestBulkCancel_MixedState_SkipsNonCancellable(t *testing.T) {
	store := continuation.NewInMemoryStore()

	cQueued := continuation.NewContinuation("dec_qu", "shell", "shell:ls").WithAgentID("agt_1")
	cQueued.State = continuation.StateQueued
	store.Create(cQueued)

	cReady := continuation.NewContinuation("dec_re", "shell", "shell:pwd").WithAgentID("agt_1")
	cReady.State = continuation.StateReady
	store.Create(cReady)

	cExecuted := continuation.NewContinuation("dec_ex", "shell", "shell:whoami").WithAgentID("agt_1")
	cExecuted.State = continuation.StateExecuted
	store.Create(cExecuted)

	cResumed := continuation.NewContinuation("dec_rs", "shell", "shell:id").WithAgentID("agt_1")
	cResumed.State = continuation.StateResumed
	store.Create(cResumed)

	cDenied := continuation.NewContinuation("dec_de", "shell", "shell:date").WithAgentID("agt_1")
	cDenied.State = continuation.StateDenied
	store.Create(cDenied)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 5 {
		t.Errorf("matched = %d, want 5", resp.Matched)
	}
	if resp.Acted != 3 {
		t.Errorf("acted = %d, want 3 (queued+ready+resumed)", resp.Acted)
	}
	if resp.Skipped != 2 {
		t.Errorf("skipped = %d, want 2 (executed+denied)", resp.Skipped)
	}
}

func TestBulkCancel_Idempotent(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateQueued
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp1 bulkCancelResponse
	json.NewDecoder(rec.Body).Decode(&resp1)
	if resp1.Acted != 2 {
		t.Errorf("first call: acted = %d, want 2", resp1.Acted)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp2 bulkCancelResponse
	json.NewDecoder(rec2.Body).Decode(&resp2)
	if resp2.Acted != 0 {
		t.Errorf("second call: acted = %d, want 0 (already cancelled)", resp2.Acted)
	}
	if resp2.Skipped != 2 {
		t.Errorf("second call: skipped = %d, want 2", resp2.Skipped)
	}
}

func TestBulkCancel_EmptyMatch(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c.State = continuation.StateExecuted
	store.Create(c)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?state=nonexistent&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 0 {
		t.Errorf("matched = %d, want 0", resp.Matched)
	}
	if resp.Acted != 0 {
		t.Errorf("acted = %d, want 0", resp.Acted)
	}
}

func TestBulkCancel_StateFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_qu", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_re", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateReady
	store.Create(c2)

	c3 := continuation.NewContinuation("dec_ex", "shell", "shell:id").WithAgentID("agt_1")
	c3.State = continuation.StateExecuted
	store.Create(c3)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?state=queued&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 1 {
		t.Errorf("matched = %d, want 1", resp.Matched)
	}
	if resp.Acted != 1 {
		t.Errorf("acted = %d, want 1", resp.Acted)
	}
}

func TestBulkCancel_ActionTypeFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "exec", "exec:whoami").WithAgentID("agt_1")
	c2.State = continuation.StateQueued
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?action_type=shell&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkCancelResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 1 {
		t.Errorf("matched = %d, want 1", resp.Matched)
	}
	if resp.Acted != 1 {
		t.Errorf("acted = %d, want 1", resp.Acted)
	}
}

func TestBulkCancel_AuditEvents(t *testing.T) {
	store := continuation.NewInMemoryStore()
	eventStore := events.NewInMemoryStore(1000)

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c1.State = continuation.StateQueued
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd").WithAgentID("agt_1")
	c2.State = continuation.StateResumed
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	h.SetEventStore(eventStore)
	h.SetGatewayID("gw_test")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if eventStore.Count() < 3 {
		t.Errorf("event count = %d, want >= 3 (2 item events + 1 batch event)", eventStore.Count())
	}
}

func TestBulkRetry_ConcurrentWithSingleOp(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.State = continuation.StateExecuted
	c.MaxRetries = 3
	store.Create(c)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	done := make(chan bool, 2)

	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/retry", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		done <- true
	}()

	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?confirm=true", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		done <- true
	}()

	<-done
	<-done

	updated, _ := store.Get(c.ContinuationID)
	if updated.RetryCount < 1 {
		t.Errorf("retry_count = %d, want >= 1", updated.RetryCount)
	}
}

func TestBulkCancel_ConcurrentWithSingleOp(t *testing.T) {
	store := continuation.NewInMemoryStore()
	c := continuation.NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")
	c.State = continuation.StateQueued
	store.Create(c)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	done := make(chan bool, 2)

	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+c.ContinuationID+"/cancel", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		done <- true
	}()

	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/continuations/cancel?confirm=true", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		done <- true
	}()

	<-done
	<-done

	updated, _ := store.Get(c.ContinuationID)
	if updated.State != continuation.StateCancelled {
		t.Errorf("state = %v, want cancelled", updated.State)
	}
}

func TestBulkRetry_SortOldest(t *testing.T) {
	store := continuation.NewInMemoryStore()

	old := continuation.NewContinuation("dec_old", "shell", "shell:ls").WithAgentID("agt_1")
	old.State = continuation.StateExecuted
	old.MaxRetries = 3
	old.CreatedAt = time.Now().UTC().Add(-1 * time.Second)
	store.Create(old)

	new := continuation.NewContinuation("dec_new", "shell", "shell:pwd").WithAgentID("agt_1")
	new.State = continuation.StateExecuted
	new.MaxRetries = 3
	store.Create(new)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?sort=oldest&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 2 {
		t.Errorf("matched = %d, want 2", resp.Matched)
	}
	if len(resp.Items) != 2 {
		t.Errorf("items count = %d, want 2", len(resp.Items))
	}
	if resp.Items[0].ContinuationID != old.ContinuationID {
		t.Errorf("first item should be oldest (dec_old)")
	}
}

func TestBulkRetry_EnvironmentFilter(t *testing.T) {
	store := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_prod", "shell", "shell:ls").WithAgentID("agt_1").WithEnvironment("production")
	c1.State = continuation.StateExecuted
	c1.MaxRetries = 3
	store.Create(c1)

	c2 := continuation.NewContinuation("dec_dev", "shell", "shell:pwd").WithAgentID("agt_1").WithEnvironment("development")
	c2.State = continuation.StateExecuted
	c2.MaxRetries = 3
	store.Create(c2)

	h := NewContinuationHandler(store)
	h.SetBulkConfig(100, 20)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/retry?environment=production&confirm=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp bulkRetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Matched != 1 {
		t.Errorf("matched = %d, want 1", resp.Matched)
	}
	if resp.Items[0].ContinuationID != c1.ContinuationID {
		t.Errorf("acted on wrong continuation")
	}
}
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/trust"
)

func TestRuntimeStatusEndpoint_MixedState(t *testing.T) {
	policyStore := policy.NewStore("test-mixed")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	eventStore := events.NewInMemoryStore(500)
	capsStore := capabilities.NewInMemoryStore()

	// Create 3 approvals with different statuses
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_mixed_1",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_mixed_2",
		ActionType:  models.ActionTypeExec,
		Resource:    "exec:whoami",
		Environment: models.EnvironmentStaging,
	})
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_mixed_3",
		ActionType:  models.ActionTypeGitPush,
		Resource:    "git:origin:master",
		Environment: models.EnvironmentProduction,
	})

	// Approve one of them
	allApprovals := approvalSvc.ListAll()
	for _, a := range allApprovals {
		if a.DecisionID == "dec_mixed_2" {
			approvalSvc.Approve(a.ApprovalID, "admin")
			break
		}
	}

	// Create continuations in different states
	c1 := continuation.NewContinuation("dec_mixed_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_mixed_2", "exec", "exec:whoami")
	c3 := continuation.NewContinuation("dec_mixed_3", "git.push", "git:origin:master")
	c4 := continuation.NewContinuation("dec_mixed_4", "shell", "shell:ps")

	c1.MarkApproved("admin")
	c1.MarkQueued()
	c2.MarkApproved("admin")
	c3.MarkDenied("admin", "too risky")
	// c4 stays in initial state (not approved)

	contStore.Create(c1)
	contStore.Create(c2)
	contStore.Create(c3)
	contStore.Create(c4)

	// Create executions in different states
	e1 := execution.NewExecution("cnt_1", "dec_mixed_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e1.MarkSucceeded(0, "ok", "")
	e2 := execution.NewExecution("cnt_2", "dec_mixed_2", "apr_2", "agt_2", "exec", "exec:whoami", 60)
	e2.MarkStarted()
	e3 := execution.NewExecution("cnt_3", "dec_mixed_3", "apr_3", "agt_3", "git.push", "git:origin", 60)
	e3.MarkFailed("err", 1)
	e4 := execution.NewExecution("cnt_4", "dec_mixed_4", "apr_4", "agt_4", "shell", "shell:ps", 60)
	e4.MarkTimedOut()

	execStore.Create(e1)
	execStore.Create(e2)
	execStore.Create(e3)
	execStore.Create(e4)

	h.SetContinuationStore(contStore)
	h.SetExecutionStore(execStore)
	h.SetApprovalService(approvalSvc)
	h.SetEventStore(eventStore)
	h.SetCapabilitiesStore(capsStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Verify approvals breakdown
	approvals, ok := resp["approvals"].(map[string]any)
	if !ok {
		t.Fatalf("approvals not a map, got %T", resp["approvals"])
	}
	pending, _ := approvals["pending"].(float64)
	approved, _ := approvals["approved"].(float64)
	denied, _ := approvals["denied"].(float64)

	if pending != 2 {
		t.Errorf("approvals.pending = %v, want 2", pending)
	}
	if approved != 1 {
		t.Errorf("approvals.approved = %v, want 1", approved)
	}
	if denied != 0 {
		t.Errorf("approvals.denied = %v, want 0", denied)
	}

	// Verify continuations by state
	conts, ok := resp["continuations"].(map[string]any)
	if !ok {
		t.Fatalf("continuations not a map, got %T", resp["continuations"])
	}

	byState, ok := conts["by_state"].(map[string]any)
	if !ok {
		t.Fatalf("continuations.by_state not a map, got %T", conts["by_state"])
	}

	queued, _ := byState["queued"].(float64)
	approvedCnt, _ := byState["approved"].(float64)
	deniedCnt, _ := byState["denied"].(float64)

	if queued != 1 {
		t.Errorf("continuations.by_state.queued = %v, want 1", queued)
	}
	if approvedCnt != 1 {
		t.Errorf("continuations.by_state.approved = %v, want 1", approvedCnt)
	}
	if deniedCnt != 1 {
		t.Errorf("continuations.by_state.denied = %v, want 1", deniedCnt)
	}

	// Verify executable and retryable counts
	executable, _ := conts["executable"].(float64)
	retryable, _ := conts["retryable"].(float64)
	if executable != 2 {
		t.Errorf("continuations.executable = %v, want 2 (c1=queued, c2=approved)", executable)
	}
	if retryable != 0 {
		t.Errorf("continuations.retryable = %v, want 0 (no executed continuations with retries)", retryable)
	}

	// Verify executions breakdown
	execs, ok := resp["executions"].(map[string]any)
	if !ok {
		t.Fatalf("executions not a map, got %T", resp["executions"])
	}

	total, _ := execs["total"].(float64)
	succeeded, _ := execs["succeeded"].(float64)
	failed, _ := execs["failed"].(float64)
	running, _ := execs["running"].(float64)
	timedOut, _ := execs["timed_out"].(float64)

	if total != 4 {
		t.Errorf("executions.total = %v, want 4", total)
	}
	if succeeded != 1 {
		t.Errorf("executions.succeeded = %v, want 1", succeeded)
	}
	if failed != 1 {
		t.Errorf("executions.failed = %v, want 1", failed)
	}
	if running != 1 {
		t.Errorf("executions.running = %v, want 1", running)
	}
	if timedOut != 1 {
		t.Errorf("executions.timed_out = %v, want 1", timedOut)
	}

	// Verify gateway info is present
	if resp["gateway_version"] == nil {
		t.Error("gateway_version should not be nil")
	}
	if resp["policy_version"] == nil {
		t.Error("policy_version should not be nil")
	}
	if resp["gateway_id"] == nil {
		t.Error("gateway_id should not be nil")
	}
}

func TestRuntimeStatusEndpoint_NilServices(t *testing.T) {
	policyStore := policy.NewStore("test-nil")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	// Don't set any services - everything should be nil-safe
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Approvals should be absent when service is nil
	if _, ok := resp["approvals"]; ok {
		t.Error("approvals should not be present when approvalSvc is nil")
	}

	// Continuations should be absent when store is nil
	if _, ok := resp["continuations"]; ok {
		t.Error("continuations should not be present when continuationStore is nil")
	}

	// Executions should be absent when store is nil
	if _, ok := resp["executions"]; ok {
		t.Error("executions should not be present when executionStore is nil")
	}

	// But gateway info should still be present
	if resp["gateway_version"] == nil {
		t.Error("gateway_version should be present")
	}
	if resp["policy_version"] == nil {
		t.Error("policy_version should be present")
	}
}

func TestRuntimeStatusEndpoint_OnlyApprovals(t *testing.T) {
	policyStore := policy.NewStore("test-approvals-only")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)

	// Create some approvals
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_1",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_2",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})

	h.SetApprovalService(approvalSvc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Should have approvals
	approvals, ok := resp["approvals"].(map[string]any)
	if !ok {
		t.Fatal("approvals should be present")
	}
	pending, _ := approvals["pending"].(float64)
	if pending != 2 {
		t.Errorf("approvals.pending = %v, want 2", pending)
	}

	// Should NOT have continuations or executions
	if _, ok := resp["continuations"]; ok {
		t.Error("continuations should not be present")
	}
	if _, ok := resp["executions"]; ok {
		t.Error("executions should not be present")
	}
}

func TestRuntimeStatusEndpoint_ContinuationRetryableExecutableCounts(t *testing.T) {
	policyStore := policy.NewStore("test-retryable")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateApproved
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateQueued
	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami")
	c3.State = continuation.StateExecuted
	c3.MaxRetries = 3
	c3.RetryCount = 1
	c4 := continuation.NewContinuation("dec_4", "shell", "shell:id")
	c4.State = continuation.StateExecuted
	c4.MaxRetries = 3
	c4.RetryCount = 3
	c5 := continuation.NewContinuation("dec_5", "shell", "shell:date")
	c5.State = continuation.StateDenied

	contStore.Create(c1)
	contStore.Create(c2)
	contStore.Create(c3)
	contStore.Create(c4)
	contStore.Create(c5)

	h.SetContinuationStore(contStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	conts, _ := resp["continuations"].(map[string]any)

	count, _ := conts["count"].(float64)
	if count != 5 {
		t.Errorf("continuations.count = %v, want 5", count)
	}

	executable, _ := conts["executable"].(float64)
	if executable != 2 {
		t.Errorf("continuations.executable = %v, want 2 (c1=approved, c2=queued)", executable)
	}

	retryable, _ := conts["retryable"].(float64)
	if retryable != 1 {
		t.Errorf("continuations.retryable = %v, want 1 (c3=executed with retries remaining)", retryable)
	}

	byState, _ := conts["by_state"].(map[string]any)
	executedCount, _ := byState["executed"].(float64)
	if executedCount != 2 {
		t.Errorf("continuations.by_state.executed = %v, want 2 (c3 and c4)", executedCount)
	}
}

func TestRuntimeStatusEndpoint_OldestTimestamps(t *testing.T) {
	policyStore := policy.NewStore("test-oldest")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)

	now := time.Now().UTC()

	c1 := continuation.NewContinuation("dec_1", "shell", "shell:ls")
	c1.State = continuation.StateApproved
	c1.CreatedAt = now.Add(-1 * time.Hour)
	c2 := continuation.NewContinuation("dec_2", "shell", "shell:pwd")
	c2.State = continuation.StateQueued
	c2.CreatedAt = now.Add(-30 * time.Minute)
	c3 := continuation.NewContinuation("dec_3", "shell", "shell:whoami")
	c3.State = continuation.StateExecuted
	c3.MaxRetries = 3
	c3.RetryCount = 1
	c3.CreatedAt = now.Add(-2 * time.Hour)
	contStore.Create(c1)
	contStore.Create(c2)
	contStore.Create(c3)

	oldApproval, _ := approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_old",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:old",
		Environment: models.EnvironmentDev,
	})
	oldApproval.CreatedAt = now.Add(-3 * time.Hour)
	approvalStore.Update(oldApproval)

	newApproval, _ := approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_new",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:new",
		Environment: models.EnvironmentDev,
	})
	newApproval.CreatedAt = now.Add(-10 * time.Minute)
	approvalStore.Update(newApproval)

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	approvals, _ := resp["approvals"].(map[string]any)
	oldestPendingStr, ok := approvals["oldest_pending_at"].(string)
	if !ok {
		t.Fatal("oldest_pending_at not present or not a string")
	}
	oldestPending, err := time.Parse(time.RFC3339, oldestPendingStr)
	if err != nil {
		t.Fatalf("failed to parse oldest_pending_at: %v", err)
	}
	expectedOldestPending := now.Add(-3 * time.Hour)
	if absDuration(oldestPending.Sub(expectedOldestPending)) > time.Minute {
		t.Errorf("oldest_pending_at = %v, expected ~%v", oldestPending, expectedOldestPending)
	}

	conts, _ := resp["continuations"].(map[string]any)
	oldestExecStr, ok := conts["oldest_executable_at"].(string)
	if !ok {
		t.Fatal("oldest_executable_at not present")
	}
	oldestExec, err := time.Parse(time.RFC3339, oldestExecStr)
	if err != nil {
		t.Fatalf("failed to parse oldest_executable_at: %v", err)
	}
	expectedOldestExec := now.Add(-1 * time.Hour)
	if absDuration(oldestExec.Sub(expectedOldestExec)) > time.Minute {
		t.Errorf("oldest_executable_at = %v, expected ~%v", oldestExec, expectedOldestExec)
	}

	oldestRetryStr, ok := conts["oldest_retryable_at"].(string)
	if !ok {
		t.Fatal("oldest_retryable_at not present")
	}
	oldestRetry, err := time.Parse(time.RFC3339, oldestRetryStr)
	if err != nil {
		t.Fatalf("failed to parse oldest_retryable_at: %v", err)
	}
	expectedOldestRetry := now.Add(-2 * time.Hour)
	if absDuration(oldestRetry.Sub(expectedOldestRetry)) > time.Minute {
		t.Errorf("oldest_retryable_at = %v, expected ~%v", oldestRetry, expectedOldestRetry)
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func TestRuntimeStatusEndpoint_OldestTimestamps_OmitWhenEmpty(t *testing.T) {
	policyStore := policy.NewStore("test-no-oldest")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	h.SetContinuationStore(contStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	conts, _ := resp["continuations"].(map[string]any)
	if _, ok := conts["oldest_executable_at"]; ok {
		t.Error("oldest_executable_at should not be present when no executable continuations")
	}
	if _, ok := conts["oldest_retryable_at"]; ok {
		t.Error("oldest_retryable_at should not be present when no retryable continuations")
	}
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestRuntimeStatusEndpoint_Approvals(t *testing.T) {
	policyStore := policy.NewStore("test-status")
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

	h.SetContinuationStore(contStore)
	h.SetExecutionStore(execStore)
	h.SetApprovalService(approvalSvc)
	h.SetEventStore(eventStore)
	h.SetCapabilitiesStore(capsStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_st_1",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})
	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_st_2",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})

	t.Log("Testing approvals via status endpoint...")

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

	approvals, ok := resp["approvals"].(map[string]any)
	if !ok {
		t.Fatalf("approvals not a map, got %T", resp["approvals"])
	}

	pending, _ := approvals["pending"].(float64)
	approved, _ := approvals["approved"].(float64)
	denied, _ := approvals["denied"].(float64)

	t.Logf("Status endpoint returned: pending=%v, approved=%v, denied=%v", pending, approved, denied)

	if pending != 2 {
		t.Errorf("approvals.pending = %v, want 2", pending)
	}
	if approved != 0 {
		t.Errorf("approvals.approved = %v, want 0", approved)
	}
	if denied != 0 {
		t.Errorf("approvals.denied = %v, want 0", denied)
	}
}

func TestRuntimeStatusEndpoint_Continuations(t *testing.T) {
	policyStore := policy.NewStore("test-status")
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

	c1 := continuation.NewContinuation("dec_st_1", "shell", "shell:ls")
	c2 := continuation.NewContinuation("dec_st_2", "exec", "exec:ls")
	c1.MarkApproved("admin")
	c1.MarkQueued()
	c2.MarkApproved("admin")
	contStore.Create(c1)
	contStore.Create(c2)

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

	conts, ok := resp["continuations"].(map[string]any)
	if !ok {
		t.Fatalf("continuations not a map, got %T", resp["continuations"])
	}

	byState, ok := conts["by_state"].(map[string]any)
	if !ok {
		t.Fatalf("continuations.by_state not a map, got %T", conts["by_state"])
	}

	queued, _ := byState["queued"].(float64)
	approved, _ := byState["approved"].(float64)

	t.Logf("Status endpoint returned: continuations.by_state.queued=%v, approved=%v", queued, approved)

	if queued != 1 {
		t.Errorf("continuations.by_state.queued = %v, want 1", queued)
	}
	if approved != 1 {
		t.Errorf("continuations.by_state.approved = %v, want 1", approved)
	}
}

func TestRuntimeStatusEndpoint_Executions(t *testing.T) {
	policyStore := policy.NewStore("test-status")
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

	e1 := execution.NewExecution("cnt_st_1", "dec_st_1", "apr_st_1", "agt_1", "shell", "shell:ls", 60)
	e1.MarkSucceeded(0, "ok", "")
	e2 := execution.NewExecution("cnt_st_2", "dec_st_2", "apr_st_2", "agt_2", "exec", "exec:ls", 60)
	e2.MarkFailed("err", 1)
	execStore.Create(e1)
	execStore.Create(e2)

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

	execs, ok := resp["executions"].(map[string]any)
	if !ok {
		t.Fatalf("executions not a map, got %T", resp["executions"])
	}

	total, _ := execs["total"].(float64)
	succeeded, _ := execs["succeeded"].(float64)
	failed, _ := execs["failed"].(float64)

	t.Logf("Status endpoint returned: executions.total=%v, succeeded=%v, failed=%v", total, succeeded, failed)

	if total != 2 {
		t.Errorf("executions.total = %v, want 2", total)
	}
	if succeeded != 1 {
		t.Errorf("executions.succeeded = %v, want 1", succeeded)
	}
	if failed != 1 {
		t.Errorf("executions.failed = %v, want 1", failed)
	}
}

func TestRuntimeStatusEndpoint_MethodNotAllowed(t *testing.T) {
	policyStore := policy.NewStore("test-status")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	h.SetApprovalService(approvalSvc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestRuntimeStatusEndpoint_Empty(t *testing.T) {
	policyStore := policy.NewStore("test-status")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
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

	approvals, ok := resp["approvals"].(map[string]any)
	if !ok {
		t.Fatalf("approvals not a map, got %T", resp["approvals"])
	}

	pending, _ := approvals["pending"].(float64)
	if pending != 0 {
		t.Errorf("approvals.pending = %v, want 0", pending)
	}
}

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

func TestRuntimeStatusEndpoint_FullResponseStructure(t *testing.T) {
	policyStore := policy.NewStore("test-full-structure")
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

	expectedFields := []string{
		"gateway_version",
		"policy_version",
		"policy_source",
		"policy_refresh_secs",
		"storage_mode",
		"decision_cache_count",
		"decision_cache_max",
		"receipt_count",
		"enrollment_file",
		"hot_reload",
		"gateway_id",
		"gateway_name",
		"enrollment_state",
		"maintenance_mode",
		"approvals",
		"continuations",
		"executions",
	}

	for _, field := range expectedFields {
		if resp[field] == nil {
			t.Errorf("expected field %q in status response", field)
		}
	}

	approvals, ok := resp["approvals"].(map[string]any)
	if !ok {
		t.Fatal("approvals should be a map")
	}
	expectedApprovalFields := []string{"pending", "approved", "denied"}
	for _, field := range expectedApprovalFields {
		if approvals[field] == nil {
			t.Errorf("expected field %q in approvals", field)
		}
	}

	conts, ok := resp["continuations"].(map[string]any)
	if !ok {
		t.Fatal("continuations should be a map")
	}
	if conts["count"] == nil {
		t.Error("expected field 'count' in continuations")
	}
	if conts["by_state"] == nil {
		t.Error("expected field 'by_state' in continuations")
	}

	execs, ok := resp["executions"].(map[string]any)
	if !ok {
		t.Fatal("executions should be a map")
	}
	expectedExecFields := []string{"total", "succeeded", "failed", "running", "timed_out"}
	for _, field := range expectedExecFields {
		if execs[field] == nil {
			t.Errorf("expected field %q in executions", field)
		}
	}

	if resp["maintenance_mode"] == nil {
		t.Error("maintenance_mode should be present")
	}
}

func TestRuntimeStatusEndpoint_WithApprovalsAndExecutions(t *testing.T) {
	policyStore := policy.NewStore("test-approvals-exec")
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

	approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_1",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	})

	e1 := execution.NewExecution("cnt_1", "dec_1", "apr_1", "agt_1", "shell", "shell:ls", 60)
	e1.MarkSucceeded(0, "ok", "")
	execStore.Create(e1)

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

	approvals, _ := resp["approvals"].(map[string]any)
	pending, _ := approvals["pending"].(float64)
	if pending != 1 {
		t.Errorf("approvals.pending = %v, want 1", pending)
	}

	execs, _ := resp["executions"].(map[string]any)
	total, _ := execs["total"].(float64)
	if total != 1 {
		t.Errorf("executions.total = %v, want 1", total)
	}
	succeeded, _ := execs["succeeded"].(float64)
	if succeeded != 1 {
		t.Errorf("executions.succeeded = %v, want 1", succeeded)
	}
}

func TestRuntimeStatusEndpoint_AllApprovalStatuses(t *testing.T) {
	policyStore := policy.NewStore("test-all-statuses")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)

	approvalStore.Create(&approval.ApprovalRequest{
		ApprovalID: "apr_pending_1",
		DecisionID: "dec_pending_1",
		Status:     approval.StatusPending,
	})
	approvalStore.Create(&approval.ApprovalRequest{
		ApprovalID: "apr_pending_2",
		DecisionID: "dec_pending_2",
		Status:     approval.StatusPending,
	})

	approved, _ := approvalSvc.CreateApproval(&approval.CreateRequest{
		DecisionID:  "dec_approved",
		ActionType:  "shell",
		Resource:    "shell:ls",
		Environment: "dev",
	})
	approvalSvc.Approve(approved.ApprovalID, "admin")

	approvalStore.Create(&approval.ApprovalRequest{
		ApprovalID: "apr_denied_1",
		DecisionID: "dec_denied_1",
		Status:     approval.StatusDenied,
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

	approvals, _ := resp["approvals"].(map[string]any)
	pending, _ := approvals["pending"].(float64)
	approvedCnt, _ := approvals["approved"].(float64)
	denied, _ := approvals["denied"].(float64)

	if pending != 2 {
		t.Errorf("approvals.pending = %v, want 2", pending)
	}
	if approvedCnt != 1 {
		t.Errorf("approvals.approved = %v, want 1", approvedCnt)
	}
	if denied != 1 {
		t.Errorf("approvals.denied = %v, want 1", denied)
	}
}

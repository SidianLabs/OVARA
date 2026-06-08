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

func setupSLAHandler(t *testing.T) (*Handler, *continuation.InMemoryStore, *approval.InMemoryStore, http.Handler) {
	t.Helper()
	policyStore := policy.NewStore("test-sla")
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
	return h, contStore, approvalStore, mux
}

func TestRuntimeStatus_SLABreach_UnderThreshold_NoBreach(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 60
	cfg.SLARetryableMaxAgeMin = 60

	policyStore := policy.NewStore("test-sla-under")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	a := &approval.ApprovalRequest{
		ApprovalID:   "apr_fresh",
		DecisionID:    "dec_1",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-30 * time.Minute),
	}
	approvalStore.Create(a)

	c := continuation.NewContinuation("dec_2", "shell", "shell:ls")
	c.CreatedAt = time.Now().UTC().Add(-30 * time.Minute)
	c.State = continuation.StateResumed
	c.RetryCount = 1
	c.MaxRetries = 3
	contStore.Create(c)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla, ok := resp["sla"].(map[string]any)
	if !ok {
		t.Fatal("sla section missing from status response")
	}
	if sla["approvals_breaching"].(float64) != 0 {
		t.Errorf("approvals_breaching = %v, want 0 (30min < 60min threshold)", sla["approvals_breaching"])
	}
	if sla["retryable_breaching"].(float64) != 0 {
		t.Errorf("retryable_breaching = %v, want 0 (30min < 60min threshold)", sla["retryable_breaching"])
	}
}

func TestRuntimeStatus_SLABreach_OverThreshold_BreachCounted(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 30
	cfg.SLARetryableMaxAgeMin = 30

	policyStore := policy.NewStore("test-sla-over")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	a1 := &approval.ApprovalRequest{
		ApprovalID:   "apr_old_1",
		DecisionID:    "dec_old_1",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-45 * time.Minute),
	}
	a2 := &approval.ApprovalRequest{
		ApprovalID:   "apr_old_2",
		DecisionID:    "dec_old_2",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-60 * time.Minute),
	}
	approvalStore.Create(a1)
	approvalStore.Create(a2)

	c := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c.CreatedAt = time.Now().UTC().Add(-45 * time.Minute)
	c.State = continuation.StateResumed
	c.RetryCount = 1
	c.MaxRetries = 3
	contStore.Create(c)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla, ok := resp["sla"].(map[string]any)
	if !ok {
		t.Fatal("sla section missing from status response")
	}
	if sla["approvals_breaching"].(float64) != 2 {
		t.Errorf("approvals_breaching = %v, want 2 (both pending > 30min old)", sla["approvals_breaching"])
	}
	if sla["retryable_breaching"].(float64) != 1 {
		t.Errorf("retryable_breaching = %v, want 1 (retryable > 30min old)", sla["retryable_breaching"])
	}
}

func TestRuntimeStatus_SLABreach_EmptyStores_ZeroCounts(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 30
	cfg.SLARetryableMaxAgeMin = 30

	policyStore := policy.NewStore("test-sla-empty")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla, ok := resp["sla"].(map[string]any)
	if !ok {
		t.Fatal("sla section missing from status response with empty stores")
	}
	if sla["approvals_breaching"].(float64) != 0 {
		t.Errorf("approvals_breaching = %v, want 0 with empty store", sla["approvals_breaching"])
	}
	if sla["retryable_breaching"].(float64) != 0 {
		t.Errorf("retryable_breaching = %v, want 0 with empty store", sla["retryable_breaching"])
	}
}

func TestRuntimeHealthEndpoint_NoBreach_Healthy(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 60
	cfg.SLARetryableMaxAgeMin = 60

	policyStore := policy.NewStore("test-health-ok")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["healthy"] != true {
		t.Errorf("healthy = %v, want true", resp["healthy"])
	}
	if resp["sla"] == nil {
		t.Error("sla section missing from health response")
	}
}

func TestRuntimeHealthEndpoint_WithBreach_Unhealthy(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 30
	cfg.SLARetryableMaxAgeMin = 30

	policyStore := policy.NewStore("test-health-breach")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	a := &approval.ApprovalRequest{
		ApprovalID:   "apr_old",
		DecisionID:    "dec_old",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-60 * time.Minute),
	}
	approvalStore.Create(a)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla := resp["sla"].(map[string]any)
	if sla["approvals_breaching"].(float64) == 0 {
		t.Error("approvals_breaching should be > 0 but got 0")
	}
}

func TestRuntimeHealthEndpoint_MaintenanceMode_Unhealthy(t *testing.T) {
	cfg := config.Default()
	h := New(nil, nil, cfg, nil)
	h.SetMaintenanceMode(true)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["healthy"] != false {
		t.Errorf("healthy = %v, want false in maintenance mode", resp["healthy"])
	}
	if resp["reason"] != "maintenance_mode" {
		t.Errorf("reason = %v, want maintenance_mode", resp["reason"])
	}
}

func TestRuntimeStatus_SLAThresholds_DefaultValues(t *testing.T) {
	cfg := config.Default()

	if cfg.SLAApprovalMaxAgeMin != 30 {
		t.Errorf("default SLAApprovalMaxAgeMin = %d, want 30", cfg.SLAApprovalMaxAgeMin)
	}
	if cfg.SLARetryableMaxAgeMin != 60 {
		t.Errorf("default SLARetryableMaxAgeMin = %d, want 60", cfg.SLARetryableMaxAgeMin)
	}
	if cfg.SLAPendingApprovalMaxAgeMin != 30 {
		t.Errorf("default SLAPendingApprovalMaxAgeMin = %d, want 30", cfg.SLAPendingApprovalMaxAgeMin)
	}
}

func TestRuntimeStatus_SLABreach_SomeItemsNotBreaching(t *testing.T) {
	cfg := config.Default()
	cfg.SLAApprovalMaxAgeMin = 30
	cfg.SLARetryableMaxAgeMin = 30

	policyStore := policy.NewStore("test-sla-mixed")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	approvalStore := approval.NewInMemoryStore()
	approvalSvc := approval.NewService(approvalStore)
	contStore := continuation.NewInMemoryStore()

	h.SetContinuationStore(contStore)
	h.SetApprovalService(approvalSvc)

	a1 := &approval.ApprovalRequest{
		ApprovalID:   "apr_fresh",
		DecisionID:    "dec_fresh",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-10 * time.Minute),
	}
	a2 := &approval.ApprovalRequest{
		ApprovalID:   "apr_old",
		DecisionID:    "dec_old",
		ActionType:   models.ActionTypeShell,
		Resource:     "shell:ls",
		Environment:  models.EnvironmentDev,
		Status:       approval.StatusPending,
		CreatedAt:    time.Now().UTC().Add(-60 * time.Minute),
	}
	approvalStore.Create(a1)
	approvalStore.Create(a2)

	c1 := continuation.NewContinuation("dec_executed", "shell", "shell:ls")
	c1.CreatedAt = time.Now().UTC().Add(-10 * time.Minute)
	c1.State = continuation.StateResumed
	c1.RetryCount = 1
	c1.MaxRetries = 3
	c2 := continuation.NewContinuation("dec_old", "shell", "shell:ls")
	c2.CreatedAt = time.Now().UTC().Add(-60 * time.Minute)
	c2.State = continuation.StateResumed
	c2.RetryCount = 1
	c2.MaxRetries = 3
	contStore.Create(c1)
	contStore.Create(c2)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla := resp["sla"].(map[string]any)
	if sla["approvals_breaching"].(float64) != 1 {
		t.Errorf("approvals_breaching = %v, want 1 (only apr_old > 30min)", sla["approvals_breaching"])
	}
	if sla["retryable_breaching"].(float64) != 1 {
		t.Errorf("retryable_breaching = %v, want 1 (only c2 > 30min)", sla["retryable_breaching"])
	}
}
func TestRuntimeStatus_SLABreach_Executing_BreachCounted(t *testing.T) {
	cfg := config.Default()
	cfg.SLAExecutingMaxAgeMin = 5

	policyStore := policy.NewStore("test-sla-exec")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	h.SetContinuationStore(contStore)

	// One stuck execution > 5 min old
	c1 := continuation.NewContinuation("dec_stuck_1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.CreatedAt = time.Now().UTC().Add(-10 * time.Minute)
	contStore.Create(c1)

	// One fresh execution (< 5 min) — not breaching
	c2 := continuation.NewContinuation("dec_stuck_2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuting
	c2.CreatedAt = time.Now().UTC().Add(-1 * time.Minute)
	contStore.Create(c2)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	sla, ok := resp["sla"].(map[string]any)
	if !ok {
		t.Fatal("sla section missing from status response")
	}
	if sla["executing_breaching"].(float64) != 1 {
		t.Errorf("executing_breaching = %v, want 1 (only c1 is > 5 min old)", sla["executing_breaching"])
	}
	if sla["executing_threshold_min"].(float64) != 5 {
		t.Errorf("executing_threshold_min = %v, want 5", sla["executing_threshold_min"])
	}
}

func TestRuntimeStatus_Executing_VisibleInContinuationStats(t *testing.T) {
	cfg := config.Default()
	policyStore := policy.NewStore("test-exec-visible")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	h.SetContinuationStore(contStore)

	// Two executing
	c1 := continuation.NewContinuation("dec_e1", "shell", "shell:ls")
	c1.State = continuation.StateExecuting
	c1.CreatedAt = time.Now().UTC().Add(-3 * time.Minute)
	contStore.Create(c1)

	c2 := continuation.NewContinuation("dec_e2", "shell", "shell:pwd")
	c2.State = continuation.StateExecuting
	c2.CreatedAt = time.Now().UTC().Add(-1 * time.Minute)
	contStore.Create(c2)

	// One approved (not executing)
	c3 := continuation.NewContinuation("dec_e3", "shell", "shell:whoami")
	c3.MarkApproved("admin")
	contStore.Create(c3)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	conts, ok := resp["continuations"].(map[string]any)
	if !ok {
		t.Fatal("continuations section missing")
	}
	if conts["executing"].(float64) != 2 {
		t.Errorf("continuations.executing = %v, want 2", conts["executing"])
	}
	byState := conts["by_state"].(map[string]any)
	if byState["executing"].(float64) != 2 {
		t.Errorf("by_state.executing = %v, want 2", byState["executing"])
	}
	if _, ok := conts["oldest_executing_at"].(string); !ok {
		t.Error("oldest_executing_at should be present when there are executing continuations")
	}
}

func TestRuntimeStatus_Executing_NoExecuting_OmitsField(t *testing.T) {
	cfg := config.Default()
	policyStore := policy.NewStore("test-exec-empty")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	h := New(eval, nil, cfg, receiptsStore)

	contStore := continuation.NewInMemoryStore()
	h.SetContinuationStore(contStore)

	c := continuation.NewContinuation("dec_a", "shell", "shell:ls")
	c.MarkApproved("admin")
	contStore.Create(c)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	conts, ok := resp["continuations"].(map[string]any)
	if !ok {
		t.Fatal("continuations section missing")
	}
	if conts["executing"].(float64) != 0 {
		t.Errorf("continuations.executing = %v, want 0", conts["executing"])
	}
	if _, present := conts["oldest_executing_at"]; present {
		t.Error("oldest_executing_at should be omitted when no executing continuations exist")
	}
}

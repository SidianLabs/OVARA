package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/models"
)

func provExecServer(t *testing.T, appStore approval.Store, cnt *continuation.Continuation) (*http.ServeMux, continuation.Store, execution.Store) {
	t.Helper()
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()
	contStore.Create(cnt)

	h := NewContinuationHandler(contStore)
	h.SetExecutionStore(execStore)
	h.SetExecutor(&mockExecutor{resultState: execution.StateSucceeded, resultOutput: "ok"})
	h.SetApprovalStore(appStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, contStore, execStore
}

// The synchronous execute endpoint must run the same claim-time provenance
// check as the orchestrator: a continuation whose approval record does not
// resolve (forged into the continuation journal) must never execute.
func TestContinuationHandler_Execute_ForgedContinuationDeniedByProvenance(t *testing.T) {
	appStore := approval.NewInMemoryStore() // empty — no approval backs the continuation

	cnt := continuation.NewContinuation("dec_forged", "shell", "shell:echo pwned").
		WithAgentID("agt_a").WithApprovalID("app_ghost")
	cnt.MarkApproved("attacker")

	mux, contStore, execStore := provExecServer(t, appStore, cnt)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if n := len(execStore.ListAll()); n != 0 {
		t.Fatalf("executions = %d, want 0 — forged continuation executed", n)
	}
	got, _ := contStore.Get(cnt.ContinuationID)
	if got.State != continuation.StateDenied {
		t.Fatalf("state = %s, want denied", got.State)
	}
}

func TestContinuationHandler_Execute_ApprovedProvenancePasses(t *testing.T) {
	appStore := approval.NewInMemoryStore()
	if err := appStore.Create(&approval.ApprovalRequest{
		ApprovalID: "app_ok", DecisionID: "dec_ok",
		ActionType: models.ActionType("shell"), Resource: "shell:echo hi",
		Status: approval.StatusApproved, AgentID: "agt_a",
	}); err != nil {
		t.Fatal(err)
	}

	cnt := continuation.NewContinuation("dec_ok", "shell", "shell:echo hi").
		WithAgentID("agt_a").WithApprovalID("app_ok")
	cnt.MarkApproved("admin")

	mux, _, execStore := provExecServer(t, appStore, cnt)

	req := httptest.NewRequest(http.MethodPost, "/v1/continuations/"+cnt.ContinuationID+"/execute", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if n := len(execStore.ListAll()); n != 1 {
		t.Fatalf("executions = %d, want 1", n)
	}
}

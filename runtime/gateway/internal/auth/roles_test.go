package auth

// SEC-0018 regression — split authorization domains. The agent/proxy token
// must reach exactly the three endpoints the executor proxy calls and
// nothing else; the operator token reaches everything. New routes default
// to operator-only (fail-safe).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func roleRig(t *testing.T) (*Middleware, http.Handler) {
	t.Helper()
	mw := NewMiddlewareWithAgents([]string{"op-token"}, []string{"agent-token"}, true)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	return mw, mw.Authenticate(ok)
}

func req(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRoleAgent_AllowedEndpoints(t *testing.T) {
	_, h := roleRig(t)
	for _, ep := range []struct{ method, path string }{
		{"POST", "/v1/runtime/check"},
		{"POST", "/v1/runtime/batch-check"},
		{"POST", "/v1/approval/create"},
		{"GET", "/v1/approval/appr_123"},
	} {
		if rec := req(h, ep.method, ep.path, "agent-token"); rec.Code != 200 {
			t.Errorf("agent %s %s: got %d, want 200", ep.method, ep.path, rec.Code)
		}
	}
}

// The negative matrix — an agent token must never reach a privileged
// surface. Each row maps to a SEC-0018/SEC-0016 abuse path.
func TestRoleAgent_OperatorEndpointsDenied(t *testing.T) {
	_, h := roleRig(t)
	for _, ep := range []struct{ method, path string }{
		// approval resolution — the SEC-0016 self-approve step
		{"POST", "/v1/approval/appr_1/approve"},
		{"POST", "/v1/approval/appr_1/deny"},
		{"POST", "/v1/approval/appr_1/resume"},
		{"GET", "/v1/approval/pending"},
		{"GET", "/v1/approvals"},
		// execution
		{"POST", "/v1/continuations/cnt_1/execute"},
		{"POST", "/v1/continuations/cnt_1/enqueue"},
		{"POST", "/v1/continuations/cnt_1/retry"},
		{"POST", "/v1/continuations/queue/pause"},
		{"GET", "/v1/continuations"},
		{"GET", "/v1/executions"},
		// policy takeover — SEC-0020
		{"POST", "/v1/policy/candidate/load"},
		{"POST", "/v1/policy/candidate/promote"},
		{"POST", "/v1/policy/rollback"},
		{"POST", "/v1/policy/restore"},
		{"POST", "/v1/policy/validate"},
		{"POST", "/v1/policy/simulate"},
		{"GET", "/v1/policy/rules"},
		{"GET", "/v1/policy/history"},
		// admin + shield + capabilities
		{"POST", "/v1/admin/sweep/events"},
		{"POST", "/v1/admin/compact"},
		{"POST", "/v1/admin/reconcile/executions"},
		{"POST", "/v1/shield/restrict"},
		{"POST", "/v1/capabilities/revoke"},
		{"POST", "/v1/capabilities/revoke-by-subject"},
		{"POST", "/v1/capabilities/track"},
		{"GET", "/v1/capabilities"},
		// audit / evidence / internals — bulk reads stay operator
		{"GET", "/v1/events"},
		{"GET", "/v1/events/export"},
		{"GET", "/v1/receipts"},
		{"GET", "/v1/audit/export"},
		{"GET", "/v1/runtime/status"},
		{"GET", "/v1/runtime/metrics"},
		{"GET", "/v1/runtime/snapshot"},
		{"GET", "/v1/runtime/trace"},
		{"GET", "/v1/runtime/decision/dec_1"},
		{"GET", "/v1/runtime/agent/agent-1/recent"},
	} {
		if rec := req(h, ep.method, ep.path, "agent-token"); rec.Code != http.StatusForbidden {
			t.Errorf("agent %s %s: got %d, want 403", ep.method, ep.path, rec.Code)
		}
	}
}

// Operator reaches both domains.
func TestRoleOperator_AllEndpointsAllowed(t *testing.T) {
	_, h := roleRig(t)
	for _, ep := range []struct{ method, path string }{
		{"POST", "/v1/approval/appr_1/approve"},
		{"POST", "/v1/policy/candidate/promote"},
		{"POST", "/v1/continuations/cnt_1/execute"},
		{"GET", "/v1/events/export"},
		{"POST", "/v1/runtime/check"},
		{"POST", "/v1/approval/create"},
	} {
		if rec := req(h, ep.method, ep.path, "op-token"); rec.Code != 200 {
			t.Errorf("operator %s %s: got %d, want 200", ep.method, ep.path, rec.Code)
		}
	}
}

// resolved_by must be derived from the credential, not the caller.
func TestPrincipal_StampedFromCredential(t *testing.T) {
	_, h := roleRig(t)
	var got string
	mw := NewMiddlewareWithAgents([]string{"op"}, nil, true)
	h = mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = Principal(r)
	}))
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set("Authorization", "Bearer op")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "operator" {
		t.Fatalf("Principal = %q, want operator", got)
	}
}

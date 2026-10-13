package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
)

// One agent cannot keep more than the cap of approvals waiting (429), and
// the same request while one is waiting gets that approval back.
func TestApprovalHandler_FloodControl(t *testing.T) {
	decisions := map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{}
	mk := func(id, resource, agent string) {
		req, resp := escalatedShellDecision()
		req.Resource = resource
		req.AgentIdentity = &models.AgentIdentity{Issuer: "ovara-init", SubjectID: agent}
		resp.DecisionID = id
		decisions[id] = struct {
			req  *models.ActionRequest
			resp *models.DecisionResponse
		}{req, resp}
	}
	for i := 0; i < approval.DefaultMaxPendingPerAgent+1; i++ {
		mk(fmt.Sprintf("dec_%d", i), fmt.Sprintf("shell:echo %d", i), "agent-1")
	}
	mk("dec_same", "shell:echo 0", "agent-1")
	mk("dec_other_agent", "shell:echo other", "agent-2")
	r := newRig(decisions)

	var first approval.ApprovalRequest
	for i := 0; i < approval.DefaultMaxPendingPerAgent; i++ {
		rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": fmt.Sprintf("dec_%d", i)})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i, rec.Code, rec.Body.String())
		}
		if i == 0 {
			_ = json.Unmarshal(rec.Body.Bytes(), &first)
		}
	}
	// identical to dec_0: the waiting approval comes back
	rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_same"})
	var same approval.ApprovalRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &same)
	if rec.Code != http.StatusOK || same.ApprovalID != first.ApprovalID {
		t.Fatalf("duplicate: %d id=%s want %s", rec.Code, same.ApprovalID, first.ApprovalID)
	}
	rec = post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": fmt.Sprintf("dec_%d", approval.DefaultMaxPendingPerAgent)})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": "dec_other_agent"}); rec.Code != http.StatusCreated {
		t.Fatalf("another agent: %d %s", rec.Code, rec.Body.String())
	}
	var pending struct {
		Approvals []approval.ApprovalRequest `json:"approvals"`
	}
	getJSON(t, r.mux, "/v1/approval/pending", &pending)
	if len(pending.Approvals) != approval.DefaultMaxPendingPerAgent+1 {
		t.Fatalf("pending: %d", len(pending.Approvals))
	}
	for i := 1; i < len(pending.Approvals); i++ {
		if pending.Approvals[i].CreatedAt.Before(pending.Approvals[i-1].CreatedAt) {
			t.Fatal("pending list is not oldest first")
		}
	}
}

func getJSON(t *testing.T, mux *http.ServeMux, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("GET %s: %v: %s", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

// An approval the agent stopped waiting for reads as expired, leaves the
// pending list, and approving it is refused with a clear error.
func TestApprovalHandler_ExpiredApproval(t *testing.T) {
	req, resp := escalatedShellDecision()
	r := newRig(map[string]struct {
		req  *models.ActionRequest
		resp *models.DecisionResponse
	}{resp.DecisionID: {req, resp}})
	now := time.Now().UTC()
	r.svc.SetNow(func() time.Time { return now })

	rec := post(t, r.mux, "/v1/approval/create", map[string]any{"decision_id": resp.DecisionID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created approval.ApprovalRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	now = now.Add(approval.DefaultPendingTTL + time.Second)

	var got approval.ApprovalRequest
	if code := getJSON(t, r.mux, "/v1/approval/"+created.ApprovalID, &got); code != http.StatusOK || got.Status != approval.StatusExpired {
		t.Fatalf("GET: %d status=%q", code, got.Status)
	}
	var pending struct {
		Count int `json:"count"`
	}
	getJSON(t, r.mux, "/v1/approval/pending", &pending)
	if pending.Count != 0 {
		t.Fatalf("expired approval still pending (count %d)", pending.Count)
	}
	rec = post(t, r.mux, "/v1/approval/"+created.ApprovalID+"/approve", map[string]any{})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("approve expired: %d %s", rec.Code, rec.Body.String())
	}
	if code := getJSON(t, r.mux, "/v1/approval/"+created.ApprovalID, &got); code != http.StatusOK || got.Status != approval.StatusExpired {
		t.Fatalf("after refused approve: status=%q", got.Status)
	}
}

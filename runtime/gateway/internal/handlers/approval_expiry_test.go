package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
)

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
	json.Unmarshal(rec.Body.Bytes(), &created)

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

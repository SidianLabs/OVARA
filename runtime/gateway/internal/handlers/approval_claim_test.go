package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

// post sends a JSON body with a bearer token and decodes the answer.
func (st *rtStack) post(t *testing.T, token, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// An approval is used once. The owning agent claims it and goes ahead; a
// second claim answers 409; another agent cannot see it; a pending one is
// reported pending and not marked. And a request approved after its caller
// stopped waiting is not asked again: the identical request gets the
// approval back from create, claims it, and only then is a new one opened.
func TestClaim_IsSingleUseAndOwnerOnly(t *testing.T) {
	st := newRTStack(t)
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	if dr.Decision != models.DecisionEscalate {
		t.Fatalf("expected escalate, got %s %v", dr.Decision, dr.ReasonCodes)
	}
	code, created := st.post(t, rtAgentATok, "/v1/approval/create", map[string]string{"decision_id": dr.DecisionID})
	id, _ := created["approval_id"].(string)
	if code != 201 || id == "" {
		t.Fatalf("create: %d %v", code, created)
	}

	// Pending: reported, not marked.
	if code, out := st.post(t, rtAgentATok, "/v1/approval/"+id+"/claim", nil); code != 200 || out["status"] != "pending" || out["claimed"] != false {
		t.Fatalf("claim while pending: %d %v", code, out)
	}
	// Another agent: the approval reads as absent.
	if code, _ := st.post(t, rtAgentBTok, "/v1/approval/"+id+"/claim", nil); code != 404 {
		t.Fatalf("foreign claim: %d, want 404", code)
	}
	if code, _ := st.post(t, rtOpToken, "/v1/approval/"+id+"/approve", map[string]string{}); code != 200 {
		t.Fatalf("approve: %d", code)
	}

	// A late retry of the identical request gets the approval back, not a
	// new card.
	_, dr2 := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	if code, out := st.post(t, rtAgentATok, "/v1/approval/create", map[string]string{"decision_id": dr2.DecisionID}); code != 200 || out["approval_id"] != id || out["status"] != "approved" {
		t.Fatalf("create after a late approval: %d %v, want the approved %s back", code, out, id)
	}
	// Claimed once.
	if code, out := st.post(t, rtAgentATok, "/v1/approval/"+id+"/claim", nil); code != 200 || out["status"] != "approved" || out["claimed"] != true {
		t.Fatalf("first claim: %d %v", code, out)
	}
	if code, _ := st.post(t, rtAgentATok, "/v1/approval/"+id+"/claim", nil); code != 409 {
		t.Fatalf("second claim: %d, want 409", code)
	}
	// After that, the identical request is a new question.
	_, dr3 := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	if code, out := st.post(t, rtAgentATok, "/v1/approval/create", map[string]string{"decision_id": dr3.DecisionID}); code != 201 || out["approval_id"] == id {
		t.Fatalf("create after the claim: %d %v, want a new approval", code, out)
	}
}

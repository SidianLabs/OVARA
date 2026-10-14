package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// The outcome report: a caller says how an action it was allowed to run
// went, and the gateway keeps that next to the decision. Through the real
// stack (token -> middleware -> principal -> handler).

func (st *rtStack) outcome(t *testing.T, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/runtime/outcome", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("outcome request: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func eventsOfType(store *events.InMemoryStore, typ string) []*events.Event {
	var out []*events.Event
	for _, e := range store.List(0) {
		if e.EventType == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestOutcome_RecordsAnAllowedDecision(t *testing.T) {
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)

	_, dr := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))
	if dr.Decision != models.DecisionAllow {
		t.Fatalf("setup: want allow, got %s %v", dr.Decision, dr.ReasonCodes)
	}
	code, out := st.outcome(t, rtAgentATok, map[string]any{
		"decision_id": dr.DecisionID, "status": "ok", "duration_ms": 42,
	})
	if code != 200 || out["recorded"] != true {
		t.Fatalf("want 200 recorded, got %d %v", code, out)
	}
	got := eventsOfType(store, events.EventTypeActionOutcome)
	if len(got) != 1 {
		t.Fatalf("want one action.outcome event, got %d", len(got))
	}
	e := got[0]
	if e.DecisionID != dr.DecisionID || e.AgentID != agentAPrincipal() {
		t.Errorf("event binds decision %q agent %q, want %q %q", e.DecisionID, e.AgentID, dr.DecisionID, agentAPrincipal())
	}
	if e.Payload["status"] != "ok" || e.Payload["resource"] != "echo hi" || e.Payload["action_type"] != "shell" || e.Payload["decision"] != "allow" {
		t.Errorf("payload = %v", e.Payload)
	}
	if d, _ := e.Payload["duration_ms"].(int64); d != 42 {
		t.Errorf("duration_ms = %v (%T)", e.Payload["duration_ms"], e.Payload["duration_ms"])
	}

	// One report per decision: the first stands.
	code, _ = st.outcome(t, rtAgentATok, map[string]any{"decision_id": dr.DecisionID, "status": "error", "error": "later"})
	if code != 409 {
		t.Fatalf("second report: want 409, got %d", code)
	}
	if n := len(eventsOfType(store, events.EventTypeActionOutcome)); n != 1 {
		t.Fatalf("second report must not add an event, got %d", n)
	}
}

func TestOutcome_ErrorIsKeptAndBounded(t *testing.T) {
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)
	_, dr := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))
	long := strings.Repeat("x", 5000)
	code, _ := st.outcome(t, rtAgentATok, map[string]any{"decision_id": dr.DecisionID, "status": "error", "error": long})
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	e := eventsOfType(store, events.EventTypeActionOutcome)[0]
	got, _ := e.Payload["error"].(string)
	if !strings.HasPrefix(got, strings.Repeat("x", 600)) || !strings.Contains(got, "truncated") || len(got) > 800 {
		t.Errorf("error text not bounded as the approval context is: len %d", len(got))
	}
}

func TestOutcome_RefusesWhatItCannotStandFor(t *testing.T) {
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)
	_, dr := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"unknown decision", map[string]any{"decision_id": "dec_never-made", "status": "ok"}, 404},
		{"no decision id", map[string]any{"status": "ok"}, 400},
		{"bad status", map[string]any{"decision_id": dr.DecisionID, "status": "fine"}, 400},
		{"negative duration", map[string]any{"decision_id": dr.DecisionID, "status": "ok", "duration_ms": -1}, 400},
	}
	for _, c := range cases {
		if code, _ := st.outcome(t, rtAgentATok, c.body); code != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, code)
		}
	}
	if n := len(eventsOfType(store, events.EventTypeActionOutcome)); n != 0 {
		t.Fatalf("refused reports must not be recorded, got %d events", n)
	}
	// No credential at all.
	if code, _ := st.outcome(t, "", map[string]any{"decision_id": dr.DecisionID, "status": "ok"}); code != 401 {
		t.Errorf("unauthenticated: want 401, got %d", code)
	}
}

func TestOutcome_OwnerOrOperatorOnly(t *testing.T) {
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)
	_, dr := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))

	// B reports on A's decision -> 403, and the attempt is on record.
	code, _ := st.outcome(t, rtAgentBTok, map[string]any{"decision_id": dr.DecisionID, "status": "ok"})
	if code != 403 {
		t.Fatalf("foreign report: want 403, got %d", code)
	}
	viol := eventsOfType(store, events.EventTypeSecurityViolation)
	if len(viol) != 1 || viol[0].Payload["kind"] != "cross_principal_outcome" || viol[0].AgentID != agentBPrincipal() {
		t.Fatalf("want one cross_principal_outcome violation by B, got %v", viol)
	}
	// The decision is still open for its owner's report.
	if code, _ := st.outcome(t, rtAgentATok, map[string]any{"decision_id": dr.DecisionID, "status": "ok"}); code != 200 {
		t.Fatalf("owner after a foreign attempt: want 200, got %d", code)
	}

	// An operator may report on any decision (a harness run by the operator).
	_, dr2 := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))
	if code, _ := st.outcome(t, rtOpToken, map[string]any{"decision_id": dr2.DecisionID, "status": "ok"}); code != 200 {
		t.Fatalf("operator report: want 200, got %d", code)
	}
}

func TestOutcome_ForADeniedDecisionIsASecurityEvent(t *testing.T) {
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)

	st.policy.AddRule(policy.Rule{ActionType: "tool.call", Environment: "*", Resource: "tool:delete_everything", Deny: true})

	req := baseReq(agentAPrincipal())
	req.ActionType = "tool.call"
	req.Resource = "tool:delete_everything"
	_, dr := st.check(t, rtAgentATok, req)
	if dr.Decision != models.DecisionDeny {
		t.Fatalf("setup: want deny, got %s %v", dr.Decision, dr.ReasonCodes)
	}
	code, _ := st.outcome(t, rtAgentATok, map[string]any{"decision_id": dr.DecisionID, "status": "ok"})
	if code != 409 {
		t.Fatalf("outcome for a denied decision: want 409, got %d", code)
	}
	if n := len(eventsOfType(store, events.EventTypeActionOutcome)); n != 0 {
		t.Fatalf("a denied decision must not get an outcome event, got %d", n)
	}
	viol := eventsOfType(store, events.EventTypeSecurityViolation)
	if len(viol) != 1 || viol[0].Payload["kind"] != "outcome_for_denied_decision" ||
		viol[0].DecisionID != dr.DecisionID || viol[0].AgentID != agentAPrincipal() {
		t.Fatalf("want one outcome_for_denied_decision violation naming the decision and agent, got %v", viol)
	}
}

func TestOutcome_EscalatedDecisionIsReportable(t *testing.T) {
	// The runtime handler cannot see whether the approval was claimed; an
	// escalated decision that was approved is run by the caller and reported
	// here, so the report is taken and carries the decision.
	st := newRTStack(t)
	store := events.NewInMemoryStore(0)
	st.handler.SetEventStore(store)
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	if dr.Decision != models.DecisionEscalate {
		t.Fatalf("setup: want escalate, got %s", dr.Decision)
	}
	code, _ := st.outcome(t, rtAgentATok, map[string]any{"decision_id": dr.DecisionID, "status": "ok", "duration_ms": 7})
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	e := eventsOfType(store, events.EventTypeActionOutcome)[0]
	if e.Payload["decision"] != "escalate" {
		t.Errorf("payload decision = %v", e.Payload["decision"])
	}
}

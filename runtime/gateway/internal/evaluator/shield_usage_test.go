package evaluator

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/trust"
)

func shellReq(agent string) *models.ActionRequest {
	return &models.ActionRequest{
		Nonce:         uuid.NewString(),
		IssuedAt:      time.Now(),
		ActionType:    models.ActionTypeShell,
		Resource:      "repo:acme/api",
		Environment:   models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{Issuer: "ovara", SubjectID: agent},
	}
}

// Normal use of a checkpoint produces escalations (a human is asked). They are
// the checkpoint working, not suspicious behaviour, so they must not push the
// agent toward quarantine. Previously three escalations restricted the agent,
// after which every request needed a human.
func TestEvaluator_EscalationsDoNotAccumulateRisk(t *testing.T) {
	ss := trust.NewShieldStore()
	ev := NewWithShield(policy.NewStore("test"), ss)

	for i := 0; i < 15; i++ {
		resp, err := ev.Evaluate(shellReq("agent-1"))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision != models.DecisionEscalate {
			t.Fatalf("request %d: want escalate, got %s", i, resp.Decision)
		}
	}
	if n := ss.GetRiskCount("agent-1"); n != 0 {
		t.Fatalf("15 escalations produced %d risk events; they are not risk", n)
	}
	if ss.IsRestricted("agent-1") {
		t.Fatal("an agent that was only ever asked to get approval must not be restricted")
	}
}

// Denials are still risk events: probing blocked targets repeatedly should
// still trip the shield.
func TestEvaluator_DenialsStillCountAsRisk(t *testing.T) {
	ss := trust.NewShieldStore()
	store := storeFromConfig(t, map[string]any{
		"version": "v1",
		"rules":   []map[string]any{{"action_type": "shell", "environment": "*", "deny": true}},
	})
	ev := NewWithShield(store, ss)
	for i := 0; i < 11; i++ {
		if _, err := ev.Evaluate(shellReq("agent-2")); err != nil {
			t.Fatal(err)
		}
	}
	if ss.GetRiskCount("agent-2") < 10 || !ss.IsRestricted("agent-2") {
		t.Fatalf("repeated denials must still restrict: risk=%d restricted=%v", ss.GetRiskCount("agent-2"), ss.IsRestricted("agent-2"))
	}
}

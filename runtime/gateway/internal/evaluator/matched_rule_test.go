package evaluator

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// Simulate names the rule that decided, so a person can see *why*
// (`ovara policy test`): deny beats allow beats escalate, and an
// unmatched request escalates with no rule named.
func TestSimulate_NamesDecidingRule(t *testing.T) {
	store := policy.NewStore("t")
	store.ClearRules()
	store.AddRule(policy.Rule{ActionType: "http.request", Environment: "*", Resource: "GET *", Allow: true, Description: "reads ok"})
	store.AddRule(policy.Rule{ActionType: "http.request", Environment: "*", Resource: "*://pastebin.com/*", Deny: true, Description: "no paste sites"})
	store.AddRule(policy.Rule{ActionType: "http.request", Environment: "*", Resource: "POST *", Escalate: true})
	ev := New(store)

	cases := []struct {
		resource string
		decision models.Decision
		rule     string
	}{
		{"GET https://pypi.org/simple/", models.DecisionAllow, "reads ok"},
		{"GET https://pastebin.com/raw/x", models.DecisionDeny, "no paste sites"},
		{"POST https://api.github.com/x", models.DecisionEscalate, "POST *"}, // no description → pattern
		{"PUT https://api.github.com/x", models.DecisionEscalate, ""},        // unmatched → default
	}
	for _, c := range cases {
		res, err := ev.Simulate(&models.ActionRequest{
			Nonce: uuid.NewString(), IssuedAt: time.Now(),
			ActionType: "http.request", Resource: c.resource, Environment: models.EnvironmentDev,
			AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
		}, store)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != c.decision || res.MatchedRule != c.rule {
			t.Errorf("%s: got %s / %q, want %s / %q", c.resource, res.Decision, res.MatchedRule, c.decision, c.rule)
		}
	}
}

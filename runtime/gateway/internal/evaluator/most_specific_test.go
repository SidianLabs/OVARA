package evaluator

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

func specificStore(rules ...policy.Rule) *policy.Store {
	st := policy.NewStore("t")
	st.ClearRules()
	st.SetPrecedence(policy.PrecedenceMostSpecific)
	for _, r := range rules {
		st.AddRule(r)
	}
	return st
}

func decide(t *testing.T, st *policy.Store, env models.Environment, resource string) (models.Decision, string) {
	t.Helper()
	res, err := New(st).Simulate(&models.ActionRequest{
		Nonce: uuid.NewString(), IssuedAt: time.Now(),
		ActionType: "http.request", Resource: resource, Environment: env,
		AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	return res.Decision, res.MatchedRule
}

func rule(res, effect, desc string) policy.Rule {
	r := policy.Rule{ActionType: "http.request", Environment: "*", Resource: res, Description: desc}
	switch effect {
	case "allow":
		r.Allow = true
	case "deny":
		r.Deny = true
	case "escalate":
		r.Escalate = true
	}
	return r
}

// The CI case the order-based evaluation could not express: allow exactly
// one write, refuse every other write at once.
func TestMostSpecific_AllowOneWriteDenyTheRest(t *testing.T) {
	st := specificStore(
		rule("POST https://api.github.com/repos/acme/app/pulls", "allow", "the one write"),
		rule("POST *", "deny", "no other writes"),
		rule("GET https://pypi.org/*", "allow", "reads"),
	)
	cases := []struct {
		res  string
		want models.Decision
		rule string
	}{
		{"POST https://api.github.com/repos/acme/app/pulls", models.DecisionAllow, "the one write"},
		{"POST https://api.github.com/repos/acme/app/issues", models.DecisionDeny, "no other writes"},
		{"POST https://pastebin.com/api", models.DecisionDeny, "no other writes"},
		{"GET https://pypi.org/simple/", models.DecisionAllow, "reads"},
		{"GET https://example.org/", models.DecisionEscalate, ""}, // nothing matches → default
	}
	for _, c := range cases {
		d, r := decide(t, st, models.EnvironmentDev, c.res)
		if d != c.want || r != c.rule {
			t.Errorf("%s: got %s / %q, want %s / %q", c.res, d, r, c.want, c.rule)
		}
	}
}

// A deny stays absolute when it is at least as specific as the allow.
func TestMostSpecific_SpecificDenyStillWins(t *testing.T) {
	st := specificStore(
		rule("GET https://*/*", "allow", "all reads"),
		rule("*://pastebin.com/*", "deny", "paste site"),
		rule("GET https://pastebin.com/raw/*", "allow", "a mistake"),
	)
	if d, r := decide(t, st, models.EnvironmentDev, "GET https://pastebin.com/x"); d != models.DecisionDeny || r != "paste site" {
		t.Fatalf("pastebin: %s %q", d, r)
	}
	// the longer allow beats the shorter deny: specificity is the rule,
	// and the file's author wrote the more specific one on purpose
	if d, r := decide(t, st, models.EnvironmentDev, "GET https://pastebin.com/raw/x"); d != models.DecisionAllow || r != "a mistake" {
		t.Fatalf("pastebin/raw: %s %q", d, r)
	}
}

func TestMostSpecific_TiesAndScope(t *testing.T) {
	// equal patterns: deny > allow > escalate
	st := specificStore(rule("POST *", "allow", "a"), rule("POST *", "escalate", "e"), rule("POST *", "deny", "d"))
	if d, _ := decide(t, st, models.EnvironmentDev, "POST https://x/"); d != models.DecisionDeny {
		t.Fatalf("tie: %s", d)
	}
	// exact environment beats "*" at equal pattern specificity
	st = specificStore(
		rule("POST *", "allow", "any env"),
		policy.Rule{ActionType: "http.request", Environment: "production", Resource: "POST *", Escalate: true, Description: "prod asks"},
	)
	if d, r := decide(t, st, models.EnvironmentProduction, "POST https://x/"); d != models.DecisionEscalate || r != "prod asks" {
		t.Fatalf("prod: %s %q", d, r)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, "POST https://x/"); d != models.DecisionAllow {
		t.Fatalf("dev: %s", d)
	}
	// a rule for another action type never applies
	st = specificStore(policy.Rule{ActionType: "shell", Environment: "*", Resource: "*", Deny: true})
	if d, _ := decide(t, st, models.EnvironmentDev, "GET https://x/"); d != models.DecisionEscalate {
		t.Fatalf("other action type: %s", d)
	}
}

func TestMostSpecific_DefaultDeny(t *testing.T) {
	st := specificStore(rule("GET https://pypi.org/*", "allow", "reads"))
	st.SetDefaultDecision(policy.DefaultDeny)
	if d, r := decide(t, st, models.EnvironmentDev, "GET https://example.org/"); d != models.DecisionDeny || r != "default: deny" {
		t.Fatalf("default deny: %s %q", d, r)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, "GET https://pypi.org/simple/"); d != models.DecisionAllow {
		t.Fatal("allowed read refused")
	}
}

// The order-based store is untouched: a broad deny still beats a narrow allow.
func TestOrderPrecedence_Unchanged(t *testing.T) {
	st := policy.NewStore("t")
	st.ClearRules()
	st.AddRule(rule("POST https://api.github.com/repos/acme/app/pulls", "allow", "the one write"))
	st.AddRule(rule("POST *", "deny", "no other writes"))
	if d, r := decide(t, st, models.EnvironmentDev, "POST https://api.github.com/repos/acme/app/pulls"); d != models.DecisionDeny || r != "no other writes" {
		t.Fatalf("order precedence changed: %s %q", d, r)
	}
}

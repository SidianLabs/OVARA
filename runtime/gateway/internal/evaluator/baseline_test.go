package evaluator

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// An organisation's baseline is a floor the project's policy can only
// narrow: its denies are absolute, its escalations can only be tightened,
// its allows stand unless the project has a rule, and where it says
// nothing the project decides. Decisions it makes say so.
func TestBaseline_ProjectOnlyNarrows(t *testing.T) {
	base := specificStore(
		rule("*://pastebin.com/*", "deny", "dump site"),
		rule("POST *", "escalate", "writes ask"),
		rule("GET https://pypi.org/*", "allow", "package index"),
	)
	project := specificStore(
		rule("POST https://pastebin.com/api", "allow", "the project tries to allow a dump"),
		rule("POST https://api.example.com/x", "allow", "the project allows a write"),
		rule("POST https://api.example.com/forbidden", "deny", "the project forbids a write"),
		rule("GET https://pypi.org/secret/*", "deny", "the project narrows the index"),
		rule("GET https://docs.example.com/*", "allow", "the project allows docs"),
	)
	ev := New(project)
	ev.SetBaseline(base)
	cases := []struct {
		res  string
		want models.Decision
		rule string
	}{
		{"POST https://pastebin.com/api", models.DecisionDeny, "org baseline: dump site"},
		{"GET https://pastebin.com/raw/x", models.DecisionDeny, "org baseline: dump site"},
		{"POST https://api.example.com/x", models.DecisionEscalate, "org baseline: writes ask"},
		{"POST https://api.example.com/forbidden", models.DecisionDeny, "the project forbids a write"},
		{"GET https://pypi.org/secret/k", models.DecisionDeny, "the project narrows the index"},
		{"GET https://pypi.org/simple/", models.DecisionAllow, "org baseline: package index"},
		{"GET https://docs.example.com/p", models.DecisionAllow, "the project allows docs"},
		{"GET https://unknown.example/", models.DecisionEscalate, ""},
	}
	for _, c := range cases {
		res, err := ev.Simulate(request(c.res), project)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != c.want || res.MatchedRule != c.rule {
			t.Errorf("simulate %s: %s / %q, want %s / %q", c.res, res.Decision, res.MatchedRule, c.want, c.rule)
		}
		live, err := ev.Evaluate(request(c.res))
		if err != nil {
			t.Fatal(err)
		}
		if live.Decision != c.want || live.MatchedRule != c.rule {
			t.Errorf("evaluate %s: %s / %q, want %s / %q", c.res, live.Decision, live.MatchedRule, c.want, c.rule)
		}
	}
	// the policy hash names both layers
	alone := New(project)
	if h := ev.PolicyHash(); h == alone.PolicyHash() || len(h) != 64 {
		t.Fatalf("hash with a baseline: %q", h)
	}
	// a baseline that denies by default is an opinion about everything
	strict := specificStore(rule("GET https://pypi.org/*", "allow", "index"))
	strict.SetDefaultDecision(policy.DefaultDeny)
	ev2 := New(project)
	ev2.SetBaseline(strict)
	if res, _ := ev2.Simulate(request("GET https://docs.example.com/p"), project); res.Decision != models.DecisionDeny || !strings.HasPrefix(res.MatchedRule, "org baseline: default") {
		t.Fatalf("baseline default deny: %s / %q", res.Decision, res.MatchedRule)
	}
	// without a baseline nothing changes
	ev.SetBaseline(nil)
	if res, _ := ev.Simulate(request("POST https://api.example.com/x"), project); res.Decision != models.DecisionAllow {
		t.Fatalf("baseline removed: %s", res.Decision)
	}
}

func request(resource string) *models.ActionRequest {
	return &models.ActionRequest{
		Nonce: uuid.NewString(), IssuedAt: time.Now(),
		ActionType: "http.request", Resource: resource, Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
	}
}

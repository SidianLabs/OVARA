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

// Escalate never softens a deny, however much more literal text the
// escalate pattern has: the agent writes the command line, so it can make
// a substring pattern "more specific" by appending to its command.
func TestMostSpecific_EscalateNeverBeatsDeny(t *testing.T) {
	st := specificStore(
		policy.Rule{ActionType: "shell", Environment: "*", Resource: "shell:sudo*", Deny: true, Description: "no sudo"},
		policy.Rule{ActionType: "shell", Environment: "*", Resource: "shell:*rm -rf*", Escalate: true, Description: "rm pauses"},
		policy.Rule{ActionType: "shell", Environment: "*", Resource: "shell:ovara*", Deny: true, Description: "no ovara"},
		policy.Rule{ActionType: "shell", Environment: "*", Resource: "shell:*git push*", Escalate: true, Description: "push pauses"},
		policy.Rule{ActionType: "shell", Environment: "*", Resource: "shell:*", Allow: true, Description: "rest"},
	)
	cases := []struct {
		cmd  string
		want models.Decision
		rule string
	}{
		{"shell:sudo id", models.DecisionDeny, "no sudo"},
		{"shell:sudo id # rm -rf", models.DecisionDeny, "no sudo"},
		{"shell:ovara approve x; git push", models.DecisionDeny, "no ovara"},
		{"shell:rm -rf build", models.DecisionEscalate, "rm pauses"},
		{"shell:ls", models.DecisionAllow, "rest"},
	}
	for _, c := range cases {
		if d, r := decideAction(t, st, "shell", c.cmd); d != c.want || r != c.rule {
			t.Errorf("%s: got %s / %q, want %s / %q", c.cmd, d, r, c.want, c.rule)
		}
	}
}

// Same for URLs: a longer escalate on the same host does not turn a deny
// into a prompt.
func TestMostSpecific_URLEscalateNeverBeatsDeny(t *testing.T) {
	st := specificStore(
		rule("*://pastebin.com/*", "deny", "paste site"),
		rule("POST https://pastebin.com/api/api_post.php", "escalate", "ask"),
	)
	if d, r := decide(t, st, models.EnvironmentDev, "POST https://pastebin.com/api/api_post.php"); d != models.DecisionDeny || r != "paste site" {
		t.Fatalf("got %s %q, want deny by the paste-site rule", d, r)
	}
}

// An allow beats a less specific deny only when it names the host at
// least as precisely: a long path under a wildcard host is not "more
// specific" than a deny that names the host.
func TestMostSpecific_BroadHostAllowNeverBeatsNarrowHostDeny(t *testing.T) {
	st := specificStore(
		rule("*://pastebin.com/*", "deny", "paste site"),
		rule("GET https://*/static/assets/fonts/*", "allow", "fonts anywhere"),
		rule("GET https://pastebin.com/raw/*", "allow", "named host"),
	)
	if d, r := decide(t, st, models.EnvironmentDev, "GET https://pastebin.com/static/assets/fonts/x.woff"); d != models.DecisionDeny || r != "paste site" {
		t.Fatalf("wildcard-host allow overrode a host deny: %s %q", d, r)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, "GET https://cdn.example/static/assets/fonts/x.woff"); d != models.DecisionAllow {
		t.Fatalf("fonts elsewhere: %s", d)
	}
	// the deliberate exception still works when the allow names the host
	if d, r := decide(t, st, models.EnvironmentDev, "GET https://pastebin.com/raw/x"); d != models.DecisionAllow || r != "named host" {
		t.Fatalf("named-host allow: %s %q", d, r)
	}
}

// Escalate loses only to deny: one that is more specific than the allow
// which beat a deny still asks.
func TestMostSpecific_EscalateStillBeatsWeakerAllow(t *testing.T) {
	st := specificStore(
		rule("POST *", "deny", "no writes"),
		rule("POST https://api.github.com/repos/acme/app/*", "allow", "app writes"),
		rule("POST https://api.github.com/repos/acme/app/releases", "escalate", "releases ask"),
	)
	if d, r := decide(t, st, models.EnvironmentDev, "POST https://api.github.com/repos/acme/app/releases"); d != models.DecisionEscalate || r != "releases ask" {
		t.Fatalf("releases: %s %q", d, r)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, "POST https://api.github.com/repos/acme/app/pulls"); d != models.DecisionAllow {
		t.Fatalf("pulls: %s", d)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, "POST https://api.github.com/repos/other/app/pulls"); d != models.DecisionDeny {
		t.Fatalf("other repo: %s", d)
	}
}

// Deny (and escalate) rules written as host rules hold on every port. Allow
// rules keep exact port matching: an allow must never grow to cover a port
// its author did not write.
func TestDenyHostRuleMatchesAnyPort(t *testing.T) {
	for _, prec := range []string{policy.PrecedenceMostSpecific, policy.PrecedenceOrder} {
		st := specificStore(
			rule("*://pastebin.com/*", "deny", "paste site"),
			rule("GET https://github.com/*", "allow", "github reads"),
			rule("*://webhook.site/*", "escalate", "ask"),
		)
		st.SetPrecedence(prec)
		cases := []struct {
			res  string
			want models.Decision
		}{
			{"GET https://pastebin.com:8443/raw/x", models.DecisionDeny},
			{"GET http://pastebin.com:443/raw/x", models.DecisionDeny},
			{"POST https://pastebin.com:8080/api", models.DecisionDeny},
			{"GET https://github.com/acme", models.DecisionAllow},
			// not allowed on a port the allow did not name: default applies
			{"GET https://github.com:8443/acme", models.DecisionEscalate},
			{"GET https://webhook.site/x", models.DecisionEscalate},
		}
		for _, c := range cases {
			if d, _ := decide(t, st, models.EnvironmentDev, c.res); d != c.want {
				t.Errorf("%s: %s: got %s, want %s", prec, c.res, d, c.want)
			}
		}
		// the allow does not match the non-default port at all
		st = specificStore(rule("GET https://github.com/*", "allow", "github reads"))
		st.SetPrecedence(prec)
		st.SetDefaultDecision(policy.DefaultDeny)
		if prec == policy.PrecedenceMostSpecific {
			if d, _ := decide(t, st, models.EnvironmentDev, "GET https://github.com:8443/acme"); d != models.DecisionDeny {
				t.Errorf("allow matched a non-default port: %s", d)
			}
		}
	}
}

func decideAction(t *testing.T, st *policy.Store, action models.ActionType, resource string) (models.Decision, string) {
	t.Helper()
	res, err := New(st).Simulate(&models.ActionRequest{
		Nonce: uuid.NewString(), IssuedAt: time.Now(),
		ActionType: action, Resource: resource, Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	return res.Decision, res.MatchedRule
}

// An escalate host rule asks on any port too: a broad read allow must not
// let a non-default port skip the question. (Under "order" precedence the
// first matching rule decides, so this is a most-specific property.)
func TestEscalateHostRulesMatchAnyPort(t *testing.T) {
	for _, prec := range []string{policy.PrecedenceMostSpecific} {
		st := specificStore(
			rule("GET https://*/*", "allow", "all reads"),
			rule("*://pastebin.com/*", "escalate", "ask about the paste site"),
		)
		st.SetPrecedence(prec)
		for _, res := range []string{"GET https://pastebin.com/x", "GET https://pastebin.com:8443/x"} {
			if d, _ := decide(t, st, models.EnvironmentDev, res); d != models.DecisionEscalate {
				t.Errorf("%s: %s: got %s, want escalate", prec, res, d)
			}
		}
		if d, _ := decide(t, st, models.EnvironmentDev, "GET https://example.org:8443/x"); d != models.DecisionAllow {
			t.Errorf("%s: unrelated host on another port: got %s, want allow", prec, d)
		}
	}
}

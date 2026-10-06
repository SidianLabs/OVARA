package policy

import (
	"math/rand"
	"testing"

	"ovara.dev/v2/action"
)

var testPolicy = &Policy{
	Version: "v2-test",
	Default: Escalate,
	Rules: []Rule{
		{ID: "r-http-dev", Effect: Allow, Sel: Selector{
			Types: []string{"http.request"}, Envs: []string{"dev"},
			Resources: []string{"*"}}},
		{ID: "r-prod-deny", Effect: Deny, Sel: Selector{
			Types: []string{"*"}, Envs: []string{"production"},
			Resources: []string{"*"}}},
		{ID: "r-gh-api", Effect: RequireCap, Sel: Selector{
			Types: []string{"net.egress"}, Envs: []string{"*"},
			Resources: []string{"https://api.github.com/*"}}},
		{ID: "r-meta-deny", Effect: Deny, Sel: Selector{
			Types: []string{"net.egress"}, Envs: []string{"*"},
			Resources: []string{"http://169.254.169.254*"}}},
	},
}

func TestEvalSemantics(t *testing.T) {
	// deny dominates everything
	a := action.Action{Type: action.TypeNetEgress, Env: action.EnvProduction,
		Resource: "http://169.254.169.254/x"}
	if d := Eval(testPolicy, a, "ag_x"); d.Outcome != Deny {
		t.Fatal("prod+metadata must deny")
	}
	// allow in dev
	a = action.Action{Type: action.TypeHTTPRequest, Env: action.EnvDev,
		Resource: "https://api.github.com/x"}
	if d := Eval(testPolicy, a, "ag_x"); d.Outcome != Allow {
		t.Fatalf("dev http should allow: %+v", d)
	}
	// require_cap when allow absent
	a = action.Action{Type: action.TypeNetEgress, Env: action.EnvDev,
		Resource: "https://api.github.com/x"}
	if d := Eval(testPolicy, a, "ag_x"); d.Outcome != RequireCap {
		t.Fatalf("gh egress should require cap: %+v", d)
	}
	// default escalate for unmatched
	a = action.Action{Type: action.TypeShellExec, Env: action.EnvDev,
		Resource: "echo hi"}
	if d := Eval(testPolicy, a, "ag_x"); d.Outcome != Escalate {
		t.Fatalf("unmatched should escalate: %+v", d)
	}
}

func TestHostBoundaryMatching(t *testing.T) {
	// SEC-0010 regression: api.github.com.evil.com must NOT match *.github.com
	sel := Selector{Resources: []string{"https://*.github.com"}}
	if matchPatterns(sel.Resources, "https://api.github.com.evil.com") {
		t.Fatal("evil suffix matched")
	}
	if !matchPatterns(sel.Resources, "https://api.github.com") {
		t.Fatal("legit subdomain didn't match")
	}
}

func TestDeterminism(t *testing.T) {
	a := action.Action{Type: action.TypeShellExec, Env: action.EnvDev, Resource: "ls"}
	d1 := Eval(testPolicy, a, "ag_x")
	d2 := Eval(testPolicy, a, "ag_x")
	if d1.Outcome != d2.Outcome || d1.PolicyID != d2.PolicyID {
		t.Fatal("nondeterministic eval")
	}
}

func TestDifferentialVsReference(t *testing.T) {
	// random-policy differential: both evaluators must agree always
	types := []string{"shell.exec", "net.egress", "http.request", "fs.write"}
	envs := []string{"local", "dev", "staging", "production"}
	effects := []Effect{Allow, Deny, Escalate, RequireCap}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		p := &Policy{Default: effects[rng.Intn(4)]}
		for j := 0; j < rng.Intn(8); j++ {
			p.Rules = append(p.Rules, Rule{
				ID: string(rune('a' + j)), Effect: effects[rng.Intn(4)],
				Sel: Selector{
					Types:     []string{types[rng.Intn(len(types))]},
					Envs:      []string{envs[rng.Intn(len(envs))]},
					Resources: []string{"*"},
					Actors:    []string{"*"},
				}})
		}
		a := action.Action{
			Type:     action.Type(types[rng.Intn(len(types))]),
			Env:      action.Env(envs[rng.Intn(len(envs))]),
			Resource: "r"}
		got := Eval(p, a, "ag_x").Outcome
		want := ReferenceEval(p, a, "ag_x")
		if got != want {
			t.Fatalf("divergence on policy %d: eval=%s ref=%s", i, got, want)
		}
	}
}

func TestDiagnostics(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{ID: "a", Effect: Allow, Sel: Selector{Types: []string{"x"}, Envs: []string{"*"}, Resources: []string{"*"}, Actors: []string{"*"}}},
		{ID: "b", Effect: Deny, Sel: Selector{Types: []string{"x"}, Envs: []string{"*"}, Resources: []string{"*"}, Actors: []string{"*"}}},
		{ID: "c", Effect: Allow, Sel: Selector{Types: []string{"shell.exec"}, Envs: []string{"dev"}, Resources: []string{"*"}, Actors: []string{"*"}}},
		{ID: "d", Effect: Deny, Sel: Selector{Types: []string{"*"}, Envs: []string{"*"}, Resources: []string{"*"}, Actors: []string{"*"}}},
	}}
	diags := Diagnostics(p)
	var contra, shadow bool
	for _, d := range diags {
		if len(d) > 11 && d[:12] == "contradictio" {
			contra = true
		}
		if len(d) > 6 && d[:7] == "shadowe" {
			shadow = true
		}
	}
	if !contra {
		t.Fatal("contradiction a-vs-b not detected")
	}
	if !shadow {
		t.Fatal("shadowed allow under wildcard deny not detected")
	}
}

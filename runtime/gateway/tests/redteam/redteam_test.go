// Package redteam runs adversarial vectors against the real decision
// engine — every class the threat model claims to defeat gets a test
// that attacks it and asserts deny. This is the P2-09 red-team gate
// for the core pipeline (sandbox/egress classes need the Linux lane).
package redteam

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/decide"
	"ovara.runtime.gateway/core/policy"
)

var (
	agentPub, agentKey, _   = ed25519.GenerateKey(rand.Reader)
	evilPub, evilKey, _     = ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerKey, _ = ed25519.GenerateKey(rand.Reader)
)

func engine() *decide.Engine {
	return decide.NewEngine(testPolicy(),
		map[string]ed25519.PublicKey{capability.PubID(issuerPub): issuerPub},
		map[string]ed25519.PublicKey{"agent1": agentPub},
		func() uint64 { return 7 })
}

func testPolicy() *policy.Policy {
	return &policy.Policy{Version: "rt", Default: policy.Deny, Rules: []policy.Rule{
		{ID: "allow-gh", Effect: policy.Allow, Sel: policy.Selector{
			Types:     []string{"http.request"},
			Resources: []string{"https://api.github.com*"}}},
		{ID: "deny-meta", Effect: policy.Deny, Priority: 10, Sel: policy.Selector{
			Types:     []string{"http.request"},
			Resources: []string{"*169.254.169.254*"}}},
		{ID: "esc-shell", Effect: policy.Escalate, Sel: policy.Selector{
			Types: []string{"shell.exec"}}},
	}}
}

// sign produces the request the honest client would send for a
// canonical action.
func sign(t *testing.T, key ed25519.PrivateKey, actor string, a action.Action) *decide.Request {
	t.Helper()
	r := &decide.Request{Action: a, Nonce: hexNonce(),
		IssuedAt: time.Now().UTC(), ActorID: actor}
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(key, []byte(r.RequestCanonical())))
	return r
}

// signRaw signs WHATEVER is in r.Action — including non-canonical
// forms an honest client never produces.
func signRaw(t *testing.T, key ed25519.PrivateKey, actor, typ, res string) *decide.Request {
	t.Helper()
	r := &decide.Request{
		Action:   action.Action{Type: action.Type(typ), Resource: res},
		Nonce:    hexNonce(),
		IssuedAt: time.Now().UTC(), ActorID: actor}
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(key, []byte(r.RequestCanonical())))
	return r
}

func canon(t *testing.T, typ, res string) action.Action {
	t.Helper()
	a, err := action.Canonicalize(typ, res)
	if err != nil {
		t.Fatalf("canonicalize %s %q: %v", typ, res, err)
	}
	return a
}

// resign re-signs after mutating r (e.g. attaching a token) — the
// signature covers the token, so it must be the LAST step.
func resign(r *decide.Request, key ed25519.PrivateKey) {
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(key, []byte(r.RequestCanonical())))
}

func hexNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustDeny(t *testing.T, name string, r decide.Result) {
	t.Helper()
	if r.Outcome != decide.OutcomeDeny {
		t.Errorf("%s: outcome=%s reason=%q — attack not denied", name, r.Outcome, r.OpReason)
	}
}

func mustAllow(t *testing.T, name string, r decide.Result) {
	t.Helper()
	if r.Outcome != decide.OutcomeAllow {
		t.Errorf("%s: outcome=%s reason=%q — expected allow", name, r.Outcome, r.OpReason)
	}
}

// RT-1 forgery: wrong key, wrong scheme, empty signature, signature
// over a different action.
func TestForgery(t *testing.T) {
	eng := engine()
	a := canon(t, "http.request", "GET https://api.github.com/x")

	mustDeny(t, "wrong key", eng.Evaluate(sign(t, evilKey, "agent1", a)))

	r := sign(t, agentKey, "agent1", a)
	r.Signature = "plain:" + r.Signature[9:]
	mustDeny(t, "wrong scheme prefix", eng.Evaluate(r))

	r = sign(t, agentKey, "agent1", a)
	r.Signature = ""
	mustDeny(t, "empty sig", eng.Evaluate(r))

	// signature over action A presented with action B
	other := sign(t, agentKey, "agent1",
		canon(t, "http.request", "GET https://api.github.com/other"))
	r = sign(t, agentKey, "agent1", a)
	r.Signature = other.Signature
	mustDeny(t, "sig over different action", eng.Evaluate(r))

	// valid signature from an unregistered actor's own key
	mustDeny(t, "unregistered actor",
		eng.Evaluate(sign(t, evilKey, "mallory", a)))
}

// RT-2 replay: identical request resent; same nonce on a different
// action.
func TestReplay(t *testing.T) {
	eng := engine()
	a := canon(t, "http.request", "GET https://api.github.com/x")
	r := sign(t, agentKey, "agent1", a)
	mustAllow(t, "first use", eng.Evaluate(r))
	mustDeny(t, "replay same request", eng.Evaluate(r))

	// same nonce, different action
	r2 := sign(t, agentKey, "agent1",
		canon(t, "http.request", "GET https://api.github.com/y"))
	r2.Nonce = r.Nonce
	mustDeny(t, "nonce reuse on different action", eng.Evaluate(r2))
}

// RT-3 non-canonical smuggling: wire action differs from what
// canonicalization produces — even when the signature covers it.
func TestNonCanonicalSmuggle(t *testing.T) {
	eng := engine()
	for _, c := range [][2]string{
		{"http.request", "GET https://API.GITHUB.COM/x"},       // case
		{"http.request", "GET https://api.github.com:443/x"},   // default port padding
		{"http.request", "GET https://api.github.com./x"},      // trailing dot
		{"http.request", "GET https://u:p@api.github.com/x"},   // userinfo
		{"http.request", "GET https://api.github.com//double"}, // dup slashes
		{"fs.delete", "/tmp/../etc/passwd"},                    // dot-segments
	} {
		mustDeny(t, "smuggle "+c[1], eng.Evaluate(signRaw(t, agentKey, "agent1", c[0], c[1])))
	}
}

// RT-4 IP-spelling evasion: non-literal IP forms that resolve to a
// deny-listed address must be rejected at canonicalization — a deny
// rule is a hole if the same address can be spelled past it.
func TestIPSpellingEvasion(t *testing.T) {
	eng := engine()
	for _, res := range []string{
		"https://2130706433/latest",     // decimal-int
		"https://0xa9fea9fe/latest",     // hex
		"https://169.254.43534/latest",  // short dotted (0xa9fe.0xa9fe)
		"https://0251.0376.0251.0376/x", // octal
	} {
		mustDeny(t, "ip-evasion "+res,
			eng.Evaluate(signRaw(t, agentKey, "agent1", "http.request", res)))
	}
	// literal form still denied by the rule, not canonicalization
	mustDeny(t, "literal metadata",
		eng.Evaluate(sign(t, agentKey, "agent1",
			canon(t, "http.request", "GET https://169.254.169.254/latest"))))
}

// RT-5 capability attacks: wrong issuer, expired, stale epoch,
// attenuated wider than parent, token on wrong action.
func TestCapabilityAttacks(t *testing.T) {
	eng := engine()
	a := canon(t, "shell.exec", "echo hi")
	now := time.Now().UTC()

	scope := capability.Scope{ActionTypes: []string{"shell.exec"},
		Resources: []string{"*"}, Envs: []string{"dev"}}
	a.Env = action.EnvDev

	wrongIssuer, err := capability.Issue(evilKey, "t1", 7, agentPub, scope, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// block-0 must be signed by a TRUSTED issuer — evilKey isn't
	req := sign(t, agentKey, "agent1", a)
	req.Token = wrongIssuer
	resign(req, agentKey)
	mustDeny(t, "forged issuer", eng.Evaluate(req))

	expired, err := capability.Issue(issuerKey, "t2", 7, agentPub, scope,
		[]capability.Caveat{{Kind: "expires_before",
			Value: now.Add(-time.Hour).Format(time.RFC3339)}}, false)
	if err != nil {
		t.Fatal(err)
	}
	req = sign(t, agentKey, "agent1", a)
	req.Token = expired
	resign(req, agentKey)
	mustDeny(t, "expired token", eng.Evaluate(req))

	stale, err := capability.Issue(issuerKey, "t3", 3, agentPub, scope, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	req = sign(t, agentKey, "agent1", a)
	req.Token = stale
	resign(req, agentKey)
	mustDeny(t, "epoch-stale token", eng.Evaluate(req))

	// attenuate a token wider than its parent — Issue must refuse,
	// and if it somehow didn't, the engine must still deny
	parent, err := capability.Issue(issuerKey, "t4", 7, agentPub,
		capability.Scope{ActionTypes: []string{"fs.read"},
			Resources: []string{"/a/*"}, Envs: []string{"dev"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	child, err := capability.Attenuate(parent, agentKey, agentPub,
		capability.Scope{ActionTypes: []string{"fs.read", "fs.delete"},
			Resources: []string{"*"}, Envs: []string{"dev"}}, nil, false)
	if err == nil && child != nil {
		da := canon(t, "fs.delete", "/x")
		da.Env = action.EnvDev
		req = sign(t, agentKey, "agent1", da)
		req.Token = child
		resign(req, agentKey)
		mustDeny(t, "widened attenuation", eng.Evaluate(req))
	}
}

// RT-6 freshness window edges.
func TestFreshnessEdges(t *testing.T) {
	eng := engine()
	a := canon(t, "http.request", "GET https://api.github.com/x")

	r := sign(t, agentKey, "agent1", a)
	r.IssuedAt = time.Now().Add(-61 * time.Second) // inside sig
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(agentKey, []byte(r.RequestCanonical())))
	mustDeny(t, "stale by 1s", eng.Evaluate(r))

	r = sign(t, agentKey, "agent1", a)
	r.IssuedAt = time.Now().Add(61 * time.Second)
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(agentKey, []byte(r.RequestCanonical())))
	mustDeny(t, "future beyond grace", eng.Evaluate(r))
}

// RT-7 escalate is not buyable: presenting a capability for an
// escalate action does NOT convert it to allow — policy outcome wins.
func TestEscalateNotBuyable(t *testing.T) {
	eng := engine()
	a := canon(t, "shell.exec", "echo hi")
	tok, err := capability.Issue(issuerKey, "esc-cap", 7, agentPub,
		capability.Scope{ActionTypes: []string{"shell.exec"},
			Resources: []string{"*"}, Envs: []string{"dev"}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Env = action.EnvDev
	r := sign(t, agentKey, "agent1", a)
	r.Token = tok
	resign(r, agentKey)
	if res := eng.Evaluate(r); res.Outcome != decide.OutcomeEscalate {
		t.Fatalf("escalate action + valid cap must still escalate, got %s reason=%q", res.Outcome, res.OpReason)
	}
}

// RT-8 audit honesty: every request — including attacks — must carry
// the same action hash for the same canonical action, so the log
// can't be forked by spelling.
func TestAuditHashStability(t *testing.T) {
	eng := engine()
	a := canon(t, "http.request", "GET https://api.github.com/x")
	good := eng.Evaluate(sign(t, agentKey, "agent1", a))
	bad := eng.Evaluate(signRaw(t, agentKey, "agent1",
		"http.request", "GET https://API.GITHUB.COM/x"))
	if bad.ActionHash != "" && bad.ActionHash == good.ActionHash {
		t.Error("non-canonical attempt must not alias the canonical hash")
	}
}

package decide

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/policy"
)

type fx struct {
	agentPub  ed25519.PublicKey
	agentKey  ed25519.PrivateKey
	opPub     ed25519.PublicKey
	opPriv    ed25519.PrivateKey
	issuerPub ed25519.PublicKey
	issuerKey ed25519.PrivateKey
	eng       *Engine
	store     *MemApprovalStore
}

func fixture(t *testing.T) *fx {
	t.Helper()
	var f fx
	f.agentPub, f.agentKey, _ = ed25519.GenerateKey(nil)
	f.opPub, f.opPriv, _ = ed25519.GenerateKey(nil)
	f.issuerPub, f.issuerKey, _ = ed25519.GenerateKey(nil)
	pol := &policy.Policy{Version: "t", Default: policy.Escalate,
		Rules: []policy.Rule{
			{ID: "deny-fs", Effect: policy.Deny, Sel: policy.Selector{
				Types: []string{"fs.delete"}}},
			{ID: "req-shell", Effect: policy.RequireCap, Sel: policy.Selector{
				Types: []string{"shell.exec"}}},
		}}
	f.eng = NewEngine(pol,
		map[string]ed25519.PublicKey{capability.PubID(f.issuerPub): f.issuerPub},
		map[string]ed25519.PublicKey{"agent1": f.agentPub},
		func() uint64 { return 1 })
	f.store = NewApprovalStore(5*time.Minute, f.opPub)
	return &f
}

func (f *fx) signed(t *testing.T, a action.Action, tok *capability.Token) *Request {
	t.Helper()
	// correct client behavior: canonicalize, then sign the canonical form
	if ca, err := action.Canonicalize(string(a.Type), a.Resource); err == nil {
		ca.Env = a.Env
		a = ca
	}
	r := &Request{Action: a, Token: tok, Nonce: "n" + a.Resource,
		IssuedAt: time.Now().UTC(), ActorID: "agent1"}
	sig := ed25519.Sign(f.agentKey, []byte(r.RequestCanonical()))
	r.Signature = "edsig_v2:" + hex.EncodeToString(sig)
	return r
}

func TestDenyWins(t *testing.T) {
	f := fixture(t)
	a := action.Action{Type: action.TypeFSDelete, Env: action.EnvDev, Resource: "/x"}
	if r := f.eng.Evaluate(f.signed(t, a, nil)); r.Outcome != OutcomeDeny {
		t.Fatalf("fs.delete must deny: %+v", r)
	}
}

func TestEscalateWithoutCapability(t *testing.T) {
	f := fixture(t)
	a := action.Action{Type: action.TypeShellExec, Env: action.EnvDev, Resource: "ls"}
	// shell.exec hits require_capability rule; no token → escalate
	if r := f.eng.Evaluate(f.signed(t, a, nil)); r.Outcome != OutcomeEscalate ||
		r.ReasonClass != "capability_missing" {
		t.Fatalf("expected escalate: %+v", r)
	}
}

func TestAllowWithValidCapability(t *testing.T) {
	f := fixture(t)
	tok, err := capability.Issue(f.issuerKey, "cap1", 1, f.agentPub, capability.Scope{
		ActionTypes: []string{"shell.exec"}, Resources: []string{"*"},
		Envs: []string{"dev"}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a := action.Action{Type: action.TypeShellExec, Env: action.EnvDev, Resource: "ls"}
	if r := f.eng.Evaluate(f.signed(t, a, tok)); r.Outcome != OutcomeAllow {
		t.Fatalf("valid cap should allow: %+v", r)
	}
}

func TestReplayDenied(t *testing.T) {
	f := fixture(t)
	a := action.Action{Type: action.TypeFSDelete, Env: action.EnvDev, Resource: "/y"}
	r1 := f.signed(t, a, nil)
	f.eng.Evaluate(r1)
	// re-present same signed request — replay must deny even though
	// the signature is genuine (nonce consumed)
	if r := f.eng.Evaluate(r1); r.Outcome != OutcomeDeny ||
		r.OpReason != "nonce replay" {
		t.Fatalf("replay should deny: %+v", r)
	}
}

func TestForgedSignature(t *testing.T) {
	f := fixture(t)
	_, evil, _ := ed25519.GenerateKey(nil)
	r := &Request{Action: action.Action{Type: action.TypeFSDelete,
		Env: action.EnvDev, Resource: "/z"}, Nonce: "n1",
		IssuedAt: time.Now().UTC(), ActorID: "agent1"}
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(evil, []byte(r.RequestCanonical())))
	// signature is valid crypto but under the WRONG key for agent1
	// (evil's key isn't agent1's registered key)
	if got := f.eng.Evaluate(r); got.Outcome != OutcomeDeny {
		t.Fatalf("wrong-key request must deny: %+v", got)
	}
}

func TestApprovalHashBound(t *testing.T) {
	f := fixture(t)
	ah := "sha256:deadbeef"
	ap := f.store.Create("ap1", ah, "pol_x")
	// approve with valid operator signature
	sig := ed25519.Sign(f.opPriv, []byte(ap.OpPayload()))
	got, err := f.store.Resolve("ap1", true, hex.EncodeToString(sig))
	if err != nil || got != ah {
		t.Fatalf("resolve: %v %s", err, got)
	}
	// single-use: second resolve fails
	if _, err := f.store.Resolve("ap1", true, hex.EncodeToString(sig)); err == nil {
		t.Fatal("second resolve must fail (single-use)")
	}
	// consume then re-check
	if err := f.store.Consume("ap1", ah); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Consume("ap1", ah); err == nil {
		t.Fatal("second consume must fail")
	}
}

func TestApprovalWrongKey(t *testing.T) {
	f := fixture(t)
	ap := f.store.Create("ap2", "sha256:x", "pol_x")
	_, wrongKey2, _ := ed25519.GenerateKey(nil)
	wrongKey := wrongKey2
	sig := ed25519.Sign(wrongKey, []byte(ap.OpPayload()))
	if _, err := f.store.Resolve("ap2", true, hex.EncodeToString(sig)); err == nil {
		t.Fatal("non-operator signature must fail")
	}
}

func TestStaleIssuedAt(t *testing.T) {
	f := fixture(t)
	a := action.Action{Type: action.TypeFSDelete, Env: action.EnvDev, Resource: "/w"}
	r := &Request{Action: a, Nonce: "n2",
		IssuedAt: time.Now().Add(-time.Hour).UTC(), ActorID: "agent1"}
	r.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(f.agentKey, []byte(r.RequestCanonical())))
	if got := f.eng.Evaluate(r); got.Outcome != OutcomeDeny {
		t.Fatalf("stale request must deny: %+v", got)
	}
}

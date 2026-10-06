package capability

import (
	"crypto/ed25519"
	"testing"
	"time"

	"ovara.dev/v2/action"
)

func keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	p, k, _ := ed25519.GenerateKey(nil)
	return p, k
}

func baseScope() Scope {
	return Scope{
		ActionTypes: []string{"shell.exec", "net.egress"},
		Resources:   []string{"*"},
		Envs:        []string{"dev"},
		RatePerMin:  60,
	}
}

func TestIssueVerifyCovers(t *testing.T) {
	pub, key := keys()
	tok, err := Issue(key, "t1", 1, baseScope(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := Verify(tok, map[string]ed25519.PublicKey{PubID(pub): pub}, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := action.Action{Type: action.TypeShellExec, Resource: "echo hi", Env: action.EnvDev}
	if !eff.Covers(a) {
		t.Fatal("scope should cover shell.exec in dev")
	}
	a.Env = action.EnvProduction
	if eff.Covers(a) {
		t.Fatal("production must not be covered")
	}
}

func TestAttenuationMonotone(t *testing.T) {
	pub, key := keys()
	tok, _ := Issue(key, "t1", 1, baseScope(), nil, true)
	// narrow to only shell.exec — OK
	narrow := Scope{ActionTypes: []string{"shell.exec"}, Resources: []string{"*"},
		Envs: []string{"dev"}, RatePerMin: 30}
	child, err := Attenuate(tok, key, narrow, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(child, map[string]ed25519.PublicKey{PubID(pub): pub}, 1); err != nil {
		t.Fatal(err)
	}
	// widen env — must fail (P4)
	wide := Scope{ActionTypes: []string{"shell.exec"}, Resources: []string{"*"},
		Envs: []string{"dev", "production"}}
	if _, err := Attenuate(tok, key, wide, nil, true); err == nil {
		t.Fatal("widening must fail")
	}
	// terminal child can't delegate further (P5)
	grand := Scope{ActionTypes: []string{"shell.exec"}, Resources: []string{"*"}, Envs: []string{"dev"}}
	if _, err := Attenuate(child, key, grand, nil, true); err == nil {
		t.Fatal("terminal block delegated")
	}
}

func TestRevocationEpoch(t *testing.T) {
	pub, key := keys()
	tok, _ := Issue(key, "t1", 1, baseScope(), nil, true)
	if _, err := Verify(tok, map[string]ed25519.PublicKey{PubID(pub): pub}, 2); err == nil {
		t.Fatal("stale-epoch token must fail verify")
	}
}

func TestExpiryCaveat(t *testing.T) {
	pub, key := keys()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	tok, _ := Issue(key, "t1", 1, baseScope(),
		[]Caveat{{Kind: "expires_before", Value: past}}, true)
	if _, err := Verify(tok, map[string]ed25519.PublicKey{PubID(pub): pub}, 1); err == nil {
		t.Fatal("expired token must fail")
	}
	// widening expiry in child must fail
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	ok := expiryMonotone([]Caveat{{Kind: "expires_before", Value: future}},
		tok.Blocks[0].Caveats)
	if ok {
		t.Fatal("expiry widening accepted")
	}
}

func TestUntrustedIssuerRejected(t *testing.T) {
	_, key := keys()
	tok, _ := Issue(key, "t1", 1, baseScope(), nil, true)
	if _, err := Verify(tok, map[string]ed25519.PublicKey{}, 1); err == nil {
		t.Fatal("untrusted issuer must fail")
	}
}

func TestForgedAttenuation(t *testing.T) {
	_, key := keys()
	_, evil := keys()
	tok, _ := Issue(key, "t1", 1, baseScope(), nil, true)
	// evil signs a widening block — signature verifies but scope widens
	wide := Scope{ActionTypes: []string{"*"}, Resources: []string{"*"}, Envs: []string{"*"}}
	if _, err := Attenuate(tok, evil, wide, nil, true); err == nil {
		t.Fatal("widening block accepted")
	}
}

package evaluator

// P1.1 capability-mode enforcement tests: a valid delegation chain is a
// capability — the request must fall inside the terminal hop's effective
// scope (DELEG-37..45), and the signed terminal nonce is the replay key.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
)

var (
	delegPub  ed25519.PublicKey
	delegPriv ed25519.PrivateKey
)

func init() {
	delegPub, delegPriv, _ = ed25519.GenerateKey(nil)
}

// hopPayload mirrors identity's canonical hop payload for test signing.
// Same field order as validator.go's hopPayload (LP format): issuer,
// subject, audience, resource_scope, actions, expires_at, delegated_at,
// nonce, prev_sig_hex. The evaluator package can't reach the unexported
// helper, so the test rebuilds the identical byte stream.
func lpStr(b *[]byte, s string) {
	n := len(s)
	*b = append(*b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	*b = append(*b, s...)
}
func lpI64(b *[]byte, v int64) {
	for i := 7; i >= 0; i-- {
		*b = append(*b, byte(v>>(8*i)))
	}
}
func lpStrs(b *[]byte, ss []string) {
	n := len(ss)
	*b = append(*b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	for _, s := range ss {
		lpStr(b, s)
	}
}
func testHopPayload(auths []models.Authority, i int, prevSig string) []byte {
	a := auths[i]
	var b []byte
	lpStr(&b, a.Issuer)
	lpStr(&b, a.SubjectID)
	lpStr(&b, a.Audience)
	lpStr(&b, a.ResourceScope)
	lpStrs(&b, a.Actions)
	lpI64(&b, a.ExpiresAt.Unix())
	lpI64(&b, a.DelegatedAt.Unix())
	lpStr(&b, a.Nonce)
	lpStr(&b, prevSig)
	return b
}

func signChain(chain *models.DelegationChain) {
	prev := ""
	for i := range chain.Authorities {
		chain.Authorities[i].Signature = ed25519.Sign(delegPriv, testHopPayload(chain.Authorities, i, prev))
		prev = hexStr(chain.Authorities[i].Signature)
	}
}

func hexStr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = h[c>>4], h[c&0xf]
	}
	return string(out)
}

func delegStore(t *testing.T) *Evaluator {
	cfg := map[string]any{
		"policy_version": "test",
		"rules": []any{
			map[string]any{"action_type": "shell", "environment": "local", "allow": true},
			map[string]any{"action_type": "deploy", "environment": "local", "allow": true},
		},
	}
	ev := New(storeFromConfig(t, cfg))
	v := identity.NewValidatorWithTrustedKeys(map[string][]byte{"issuer-1": delegPub})
	ev.SetValidator(v)
	return ev
}

func delegReq(action models.ActionType, resource string, chain *models.DelegationChain) *models.ActionRequest {
	return &models.ActionRequest{
		Nonce:       uuid.NewString(),
		IssuedAt:    time.Now(),
		ActionType:  action,
		Resource:    resource,
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "ag_terminal",
		},
		DelegationChain: chain,
	}
}

func mintDeleg(actions []string, scope string, nonce string) *models.DelegationChain {
	c := &models.DelegationChain{
		Authorities: []models.Authority{{
			Issuer: "issuer-1", SubjectID: "ag_terminal",
			Actions: actions, ResourceScope: scope,
			ExpiresAt: time.Now().Add(time.Hour), DelegatedAt: time.Now(),
			Nonce: nonce,
		}},
		Depth: 1,
	}
	signChain(c)
	return c
}

// DELEG-37: valid chain + in-scope request → allow.
func TestDeleg37_ValidAuthorized(t *testing.T) {
	ev := delegStore(t)
	r := delegReq(models.ActionTypeShell, "shell:ls", mintDeleg([]string{"shell"}, "*", "n37"))
	resp, _ := ev.Evaluate(r)
	if resp.Decision != models.DecisionAllow {
		t.Fatalf("in-scope delegated request must allow, got %s reasons=%v", resp.Decision, resp.ReasonCodes)
	}
}

// DELEG-38: valid chain delegating "shell" must NOT authorize "deploy".
func TestDeleg38_WrongAction(t *testing.T) {
	ev := delegStore(t)
	r := delegReq(models.ActionType("deploy"), "deploy:prod", mintDeleg([]string{"shell"}, "*", "n38"))
	resp, _ := ev.Evaluate(r)
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("out-of-scope action must deny, got %s", resp.Decision)
	}
}

// DELEG-39: valid chain scoped repo://org/* must NOT authorize another host.
func TestDeleg39_WrongResource(t *testing.T) {
	ev := delegStore(t)
	r := delegReq(models.ActionTypeShell, "https://evil.example/x", mintDeleg([]string{"shell"}, "https://api.github.com/*", "n39"))
	resp, _ := ev.Evaluate(r)
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("out-of-scope resource must deny, got %s", resp.Decision)
	}
	inScope := delegReq(models.ActionTypeShell, "https://api.github.com/x", mintDeleg([]string{"shell"}, "https://api.github.com/*", "n39b"))
	resp2, _ := ev.Evaluate(inScope)
	if resp2.Decision != models.DecisionAllow {
		t.Fatalf("in-scope URL resource must allow, got %s", resp2.Decision)
	}
}

// DELEG-40: method-scoped delegation rejects a different method.
func TestDeleg40_WrongMethod(t *testing.T) {
	ev := delegStore(t)
	r := delegReq(models.ActionTypeShell, "DELETE https://api.github.com/x", mintDeleg([]string{"shell"}, "GET https://api.github.com/*", "n40"))
	resp, _ := ev.Evaluate(r)
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("method mismatch must deny, got %s", resp.Decision)
	}
	ok := delegReq(models.ActionTypeShell, "GET https://api.github.com/x", mintDeleg([]string{"shell"}, "GET https://api.github.com/*", "n40b"))
	if resp2, _ := ev.Evaluate(ok); resp2.Decision != models.DecisionAllow {
		t.Fatalf("matching method must allow, got %s", resp2.Decision)
	}
}

// DELEG-41: wrong audience → validator denies (expected audience set).
func TestDeleg41_WrongAudience(t *testing.T) {
	cfg := map[string]any{
		"policy_version": "test",
		"rules": []any{
			map[string]any{"action_type": "shell", "environment": "local", "allow": true},
		},
	}
	ev := New(storeFromConfig(t, cfg))
	v := identity.NewValidatorWithTrustedKeys(map[string][]byte{"issuer-1": delegPub})
	v.SetExpectedAudience("gw-A")
	ev.SetValidator(v)

	c := mintDeleg([]string{"shell"}, "*", "n41")
	c.Authorities[0].Audience = "gw-other"
	signChain(c)
	resp, _ := ev.Evaluate(delegReq(models.ActionTypeShell, "shell:x", c))
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("wrong-audience delegation must deny, got %s", resp.Decision)
	}
	c.Authorities[0].Audience = "gw-A"
	c.Authorities[0].Nonce = "n41b"
	signChain(c)
	resp2, _ := ev.Evaluate(delegReq(models.ActionTypeShell, "shell:x", c))
	if resp2.Decision != models.DecisionAllow {
		t.Fatalf("correct-audience delegation must allow, got %s", resp2.Decision)
	}
}

// DELEG-42: delegation for ag_terminal presented by a different subject → deny.
func TestDeleg42_WrongSubject(t *testing.T) {
	ev := delegStore(t)
	r := delegReq(models.ActionTypeShell, "shell:x", mintDeleg([]string{"shell"}, "*", "n42"))
	r.AgentIdentity.SubjectID = "ag_other"
	resp, _ := ev.Evaluate(r)
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("wrong-subject delegation must deny, got %s", resp.Decision)
	}
}

// DELEG-43: expired chain → deny.
func TestDeleg43_Expired(t *testing.T) {
	ev := delegStore(t)
	c := mintDeleg([]string{"shell"}, "*", "n43")
	c.Authorities[0].ExpiresAt = time.Now().Add(-time.Hour)
	signChain(c)
	resp, _ := ev.Evaluate(delegReq(models.ActionTypeShell, "shell:x", c))
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("expired delegation must deny, got %s", resp.Decision)
	}
}

// DELEG-44: valid delegation but policy denies → deny (delegation can't lift policy).
func TestDeleg44_PolicyStillDecides(t *testing.T) {
	cfg := map[string]any{
		"policy_version": "test",
		"rules": []any{
			map[string]any{"action_type": "shell", "environment": "local", "allow": false},
		},
	}
	ev := New(storeFromConfig(t, cfg))
	v := identity.NewValidatorWithTrustedKeys(map[string][]byte{"issuer-1": delegPub})
	ev.SetValidator(v)
	r := delegReq(models.ActionTypeShell, "shell:x", mintDeleg([]string{"shell"}, "*", "n44"))
	resp, _ := ev.Evaluate(r)
	if resp.Decision == models.DecisionAllow {
		t.Fatal("delegation must not lift a policy deny")
	}
}

// DELEG-11 (evaluator level): same chain replayed → second request denied.
func TestDeleg_ReplayViaEvaluator(t *testing.T) {
	ev := delegStore(t)
	c := mintDeleg([]string{"shell"}, "*", "n-replay")
	r1 := delegReq(models.ActionTypeShell, "shell:x", c)
	if resp, _ := ev.Evaluate(r1); resp.Decision != models.DecisionAllow {
		t.Fatalf("first presentation must allow, got %s", resp.Decision)
	}
	r2 := delegReq(models.ActionTypeShell, "shell:x", c) // same chain, fresh request nonce
	if resp, _ := ev.Evaluate(r2); resp.Decision != models.DecisionDeny {
		t.Fatalf("replayed delegation must deny, got %s", resp.Decision)
	}
}

// DELEG-12 (evaluator level): replay with mutated nonce → signature invalid.
func TestDeleg_ReplayMutatedNonce(t *testing.T) {
	ev := delegStore(t)
	c := mintDeleg([]string{"shell"}, "*", "n-mut")
	r1 := delegReq(models.ActionTypeShell, "shell:x", c)
	_, _ = ev.Evaluate(r1)
	c.Authorities[0].Nonce = "n-mut2" // unsigned-field mutation is now impossible
	r2 := delegReq(models.ActionTypeShell, "shell:x", c)
	if resp, _ := ev.Evaluate(r2); resp.Decision != models.DecisionDeny {
		t.Fatalf("nonce-mutated replay must deny, got %s", resp.Decision)
	}
}

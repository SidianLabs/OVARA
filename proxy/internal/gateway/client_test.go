package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The subject the proxy sends must equal the gateway's credential-derived
// principal (ag_<sha256(token)[:16]>) — a mismatch is rejected as
// identity_mismatch at bindIdentity. Regression for the P1 integration
// break where a hardcoded "egress-agent" failed every transit.
func TestSubjectIDMatchesGatewayPrincipal(t *testing.T) {
	token := "test-agent-token-abc123"
	sum := sha256.Sum256([]byte(token))
	want := "ag_" + hex.EncodeToString(sum[:])[:16]
	if got := subjectID(token); got != want {
		t.Fatalf("subjectID = %q, want %q", got, want)
	}
	if got := subjectID(""); got != "egress-agent" {
		t.Fatalf("empty-token subjectID = %q, want egress-agent", got)
	}
}

// Negative case: a subject derived from a DIFFERENT credential must not
// match — at bindIdentity that mismatch is a 400 identity_mismatch deny.
// This is the property that makes the proxy's identity honest: it can
// only ever claim the principal of the credential it actually holds.
func TestSubjectIDDifferentCredentialDenied(t *testing.T) {
	proxySubject := subjectID("proxy-gateway-token-1")
	victimSubject := subjectID("victim-agent-token-2")
	if proxySubject == victimSubject {
		t.Fatal("distinct credentials must derive distinct principals — " +
			"a collision would let the proxy claim a foreign identity")
	}
	// And it must not collide with the operator domain either.
	opSum := sha256.Sum256([]byte("proxy-gateway-token-1"))
	opPrincipal := "op_" + hex.EncodeToString(opSum[:])[:16]
	if proxySubject == opPrincipal {
		t.Fatal("agent principal collided with operator domain")
	}
}

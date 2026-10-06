package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ovara.runtime.gateway/core/decide"
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

// The proxy→gateway fold: with a request key installed, Check must send a
// signed decide.Request to /v2/runtime/check, and the signature must
// verify over the request's canonical form (server's exact check).
func TestCheckV2SendsSignedRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	var gotReq decide.Request
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/whoami" { // subject resolution pre-call
			w.Write([]byte(`{"principal_id":"ag_9bd8389a8bb5b6fd"}`))
			return
		}
		if r.URL.Path != "/v2/runtime/check" {
			t.Errorf("path = %s, want /v2/runtime/check", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Write([]byte(`{"outcome":"allow","reason_class":"policy_allow","action_hash":"h","policy_id":"p","audit_seq":7}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "agent-token", "dev")
	if err := c.SetRequestKey(hex.EncodeToString(priv)); err != nil {
		t.Fatal(err)
	}
	d, err := c.Check(context.Background(), "GET", "https://api.github.com/x")
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "allow" || gotAuth != "Bearer agent-token" {
		t.Fatalf("decision=%q auth=%q", d.Decision, gotAuth)
	}

	// Server-side verification, exactly what the engine does.
	sig := strings.TrimPrefix(gotReq.Signature, "edsig_v2:")
	sigBytes, err := hex.DecodeString(sig)
	if err != nil || !ed25519.Verify(pub, []byte(gotReq.RequestCanonical()), sigBytes) {
		t.Fatal("signature over RequestCanonical must verify with actor pubkey")
	}
	// whoami resolved the principal, overriding the hash-derived subject
	if gotReq.Action.Type != "http.request" || gotReq.ActorID != "ag_9bd8389a8bb5b6fd" {
		t.Fatalf("action=%+v actor=%q", gotReq.Action, gotReq.ActorID)
	}
	if gotReq.Action.Resource == "" || !strings.Contains(gotReq.Action.Resource, "api.github.com") {
		t.Fatalf("canonical resource malformed: %+v", gotReq.Action.Resource)
	}
	if gotReq.Nonce == "" || gotReq.IssuedAt.IsZero() {
		t.Fatal("nonce/issued_at must be populated")
	}
}

// Without a request key the client stays on the unsigned /v1 path
// (transition compat).
func TestCheckWithoutKeyStaysV1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime/check" {
			t.Errorf("path = %s, want /v1/runtime/check", r.URL.Path)
		}
		w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "dev")
	if _, err := c.Check(context.Background(), "GET", "https://api.github.com/x"); err != nil {
		t.Fatal(err)
	}
}

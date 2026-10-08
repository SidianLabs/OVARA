package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func gw(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, "tok", "dev"), srv
}

func TestCheckSendsCredentialAndParsesDecision(t *testing.T) {
	var got map[string]any
	var auth string
	c, _ := gw(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			json.NewEncoder(w).Encode(map[string]string{"principal_id": "ag_stable"})
		case "/v1/runtime/check":
			auth = r.Header.Get("Authorization")
			json.NewDecoder(r.Body).Decode(&got)
			json.NewEncoder(w).Encode(Decision{Decision: "escalate", DecisionID: "d1", ApprovalID: "a1"})
		}
	})
	d, err := c.Check(context.Background(), "POST", "https://x.example/y")
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "escalate" || d.DecisionID != "d1" || d.ApprovalID != "a1" {
		t.Fatalf("bad decision: %+v", d)
	}
	if auth != "Bearer tok" {
		t.Fatalf("Authorization = %q", auth)
	}
	if got["resource"] != "POST https://x.example/y" {
		t.Fatalf("resource = %v", got["resource"])
	}
	if id, _ := got["agent_identity"].(map[string]any); id["subject_id"] != "ag_stable" {
		t.Fatalf("subject must be the gateway-resolved principal, got %v", id)
	}
}

// Each check carries a fresh nonce; a reused one would be rejected as a replay.
func TestCheckUsesAFreshNonceEveryTime(t *testing.T) {
	seen := map[string]bool{}
	c, _ := gw(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime/check" {
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			n, _ := b["nonce"].(string)
			if n == "" || seen[n] {
				t.Errorf("empty or repeated nonce %q", n)
			}
			seen[n] = true
		}
		json.NewEncoder(w).Encode(Decision{Decision: "allow"})
	})
	for i := 0; i < 20; i++ {
		if _, err := c.Check(context.Background(), "GET", "https://x/"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNon200AndBadJSONAreErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"403":      func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) },
		"500":      func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"bad json": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{not json")) },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := gw(t, h)
			if d, err := c.Check(context.Background(), "GET", "https://x/"); err == nil {
				t.Fatalf("a gateway failure must be an error (fail-closed upstream), got %+v", d)
			}
		})
	}
}

// The principal lookup used to run once. A gateway that was not up yet left
// the proxy on the derived fallback forever.
func TestSubjectResolutionRetriesAfterTransportFailure(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"principal_id": "ag_resolved"})
	}))
	c := New("http://"+srv.Listener.Addr().String(), "tok", "dev")
	fallback := subjectID("tok")
	if got := c.resolvedSubject(); got != fallback { // not listening yet
		t.Fatalf("before the gateway is up want fallback %q, got %q", fallback, got)
	}
	srv.Start()
	defer srv.Close()
	up.Store(true)
	if got := c.resolvedSubject(); got != "ag_resolved" {
		t.Fatalf("after the gateway is up the real principal must be adopted, got %q", got)
	}
}

func TestSubjectResolutionIsFinalAfterAnHTTPAnswer(t *testing.T) {
	var calls atomic.Int32
	c, _ := gw(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(404) // older gateway without /v1/whoami
	})
	for i := 0; i < 5; i++ {
		c.resolvedSubject()
	}
	if calls.Load() != 1 {
		t.Fatalf("whoami called %d times; an HTTP answer must not be re-asked", calls.Load())
	}
}

func TestApprovalLifecycle(t *testing.T) {
	c, _ := gw(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/whoami":
			w.WriteHeader(404)
		case r.Method == "POST" && r.URL.Path == "/v1/approval/create":
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			if b["decision_id"] != "d9" {
				t.Errorf("decision_id = %v", b["decision_id"])
			}
			json.NewEncoder(w).Encode(map[string]string{"approval_id": "apr_1"})
		case r.URL.Path == "/v1/approval/apr_1":
			json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		default:
			w.WriteHeader(404)
		}
	})
	id, err := c.CreateApproval(context.Background(), &Decision{DecisionID: "d9"}, "POST", "https://x/")
	if err != nil || id != "apr_1" {
		t.Fatalf("CreateApproval = %q, %v", id, err)
	}
	st, err := c.ApprovalStatus(context.Background(), id)
	if err != nil || st != "approved" {
		t.Fatalf("ApprovalStatus = %q, %v", st, err)
	}
	if _, err := c.ApprovalStatus(context.Background(), "missing"); err == nil {
		t.Fatal("an unknown approval must be an error")
	}
}

package proxy

// SEC-0008 regression — a credentialed proxy is a credential dispenser.
// When agent_token is configured, every client must authenticate via
// Proxy-Authorization; unauthenticated requests never reach the policy
// engine, upstream, or credential injection.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.proxy/internal/creds"
)

func TestClientAuth_UnauthenticatedRejected(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	f := newFixture(t, "allow", []creds.Binding{
		{Host: mustHost(t, upstream.URL), Headers: map[string]string{"Authorization": "Bearer real"}},
	})
	f.srv.SetClientAuth("proxy-secret")

	for _, variant := range []struct {
		name  string
		setH  func(*http.Request)
	}{
		{"no header", func(*http.Request) {}},
		{"wrong basic password", func(r *http.Request) {
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:wrong")))
		}},
		{"wrong bearer", func(r *http.Request) {
			r.Header.Set("Proxy-Authorization", "Bearer wrong")
		}},
		{"empty basic", func(r *http.Request) {
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:")))
		}},
	} {
		req, _ := http.NewRequest("GET", upstream.URL+"/x", nil)
		variant.setH(req)
		rec := httptest.NewRecorder()
		f.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusProxyAuthRequired {
			t.Fatalf("%s: got %d, want 407", variant.name, rec.Code)
		}
	}
	if reached {
		t.Fatal("unauthenticated request reached upstream")
	}
}

func TestClientAuth_AuthenticatedPasses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	f := newFixture(t, "allow", nil)
	f.srv.SetClientAuth("proxy-secret")

	// Basic — what curl sends for http://agent:TOKEN@proxy:9443
	req, _ := http.NewRequest("GET", upstream.URL+"/x", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:proxy-secret")))
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("basic auth: got %d, want 200", rec.Code)
	}

	// Bearer — for non-curl clients
	req, _ = http.NewRequest("GET", upstream.URL+"/x", nil)
	req.Header.Set("Proxy-Authorization", "Bearer proxy-secret")
	rec = httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("bearer auth: got %d, want 200", rec.Code)
	}
}

// A denied receipt must be written for unauthenticated probes — a scanner
// must leave evidence.
func TestClientAuth_UnauthAttemptReceipted(t *testing.T) {
	f := newFixture(t, "allow", nil)
	f.srv.SetClientAuth("proxy-secret")

	req, _ := http.NewRequest("CONNECT", "//example.com:443", nil)
	req.Host = "example.com:443"
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("got %d, want 407", rec.Code)
	}
	r := f.lastReceipt(t)
	if r.Decision != "deny" {
		t.Fatalf("unauth probe left no deny receipt: %+v", r)
	}
}

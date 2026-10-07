package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/gateway"
)

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"Internal.Example.COM":      "internal.example.com",
		"internal.example.com.":     "internal.example.com",
		"internal.example.com:443":  "internal.example.com",
		"INTERNAL.example.com.:443": "internal.example.com",
		"[::1]:443":                 "::1",
		"10.0.0.1":                  "10.0.0.1",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The sensitive-host list used to be matched case- and dot-sensitively, so a
// trailing dot or upper-case name skipped forced approval.
func TestSensitiveHostMatchIgnoresCaseAndTrailingDot(t *testing.T) {
	globs := []string{"internal.example.com", "*.corp.example.com"}
	for _, h := range []string{
		"internal.example.com", "INTERNAL.example.com", "internal.example.com.",
		"db.corp.example.com.", "DB.Corp.Example.com",
	} {
		if !matchHostGlob(globs, h) {
			t.Errorf("%q should match the sensitive-host list", h)
		}
	}
	if matchHostGlob(globs, "example.com") {
		t.Error("unrelated host matched")
	}
}

func TestSecretTargets(t *testing.T) {
	if got := secretTargets("anthropic-version", "2023-06-01"); len(got) != 0 {
		t.Fatalf("a protocol version must not be scrubbed, got %q", got)
	}
	got := secretTargets("Authorization", "Bearer ghp_abcdef123456")
	has := func(s string) bool {
		for _, g := range got {
			if string(g) == s {
				return true
			}
		}
		return false
	}
	if !has("Bearer ghp_abcdef123456") || !has("ghp_abcdef123456") {
		t.Fatalf("both the full value and the bare token must be scrubbed, got %q", got)
	}
	if got := secretTargets("x-api-key", "short"); len(got) != 0 {
		t.Fatalf("values under 8 bytes are not scrub targets, got %q", got)
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(3, 0.0001)
	n := 0
	for i := 0; i < 10; i++ {
		if l.allow() {
			n++
		}
	}
	if n != 3 || l.dropped != 7 {
		t.Fatalf("allowed=%d dropped=%d, want 3/7", n, l.dropped)
	}
}

// An unauthenticated flood must not grow the receipt log without bound.
func TestUnauthFloodIsRateLimitedInReceipts(t *testing.T) {
	f := newFixture(t, "allow", nil)
	f.srv.SetClientAuth("secret-token")
	for i := 0; i < 200; i++ {
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "http://example.com/", nil)
		f.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusProxyAuthRequired {
			t.Fatalf("want 407, got %d", rec.Code)
		}
	}
	lines := countLines(t, f.chainFile)
	if lines > 40 {
		t.Fatalf("200 unauthenticated requests wrote %d receipts; expected the limiter to cap it near its burst", lines)
	}
	if lines == 0 {
		t.Fatal("probes must still leave some evidence")
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

// Reads that carry data (a body, or an enormous query) are escalated even
// when policy allows the verb, and never reach the upstream unapproved.
func TestReadsThatCarryDataAreEscalated(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cases := map[string]func() *http.Request{
		"GET with body": func() *http.Request {
			r, _ := http.NewRequest("GET", upstream.URL+"/x", strings.NewReader("stolen-secret-data"))
			return r
		},
		"huge query": func() *http.Request {
			r, _ := http.NewRequest("GET", upstream.URL+"/x?d="+strings.Repeat("A", maxReadQueryBytes+10), nil)
			return r
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "allow", nil)
			f.srv.SetEscalateWindow(80*time.Millisecond, 10*time.Millisecond)
			rec := httptest.NewRecorder()
			f.srv.ServeHTTP(rec, mk())
			if rec.Code == http.StatusOK {
				t.Fatalf("data-carrying read was forwarded without approval")
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream was reached %d times", hits.Load())
	}

	// A plain read is still free.
	f := newFixture(t, "allow", nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", upstream.URL+"/x?q=short", nil)
	f.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("an ordinary GET should pass, got %d", rec.Code)
	}
}

func TestMethodOverrideHeadersAreNotForwarded(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	f := newFixture(t, "allow", nil)
	req, _ := http.NewRequest("POST", upstream.URL+"/x", strings.NewReader("{}"))
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	req.Header.Set("X-Method-Override", "DELETE")
	req.Header.Set("X-HTTP-Method", "DELETE")
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	for _, h := range methodOverrideHeaders {
		if got.Get(h) != "" {
			t.Errorf("%s reached the upstream", h)
		}
	}
}

// CONNECT to a host NAME must not trigger a DNS lookup before policy runs
// (the lookup itself is an exfiltration channel); IP literals in private
// space are still refused immediately.
func TestConnectDoesNotResolveNamesBeforePolicy(t *testing.T) {
	f := newFixture(t, "deny", nil)
	f.srv.SetPublicEgressOnly(true)
	f.srv.SetConnectPort443Only(true)
	proxySrv := httptest.NewServer(f.srv)
	defer proxySrv.Close()

	status := func(target string) string {
		c, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	// A name that cannot resolve: previously a 403 produced by the lookup.
	if got := status("never-resolves-aaaa1111.invalid:443"); !strings.Contains(got, "200") {
		t.Errorf("name CONNECT should be accepted and left to policy, got %q", got)
	}
	if got := status("10.0.0.5:443"); !strings.Contains(got, "403") {
		t.Errorf("private IP literal must be refused, got %q", got)
	}
	if got := status("127.0.0.1:443"); !strings.Contains(got, "403") {
		t.Errorf("loopback literal must be refused, got %q", got)
	}
}

func TestEscalationCapRefusesWhenFull(t *testing.T) {
	f := newFixture(t, "escalate", nil)
	for i := 0; i < cap(f.srv.escalateSem); i++ {
		f.srv.escalateSem <- struct{}{}
	}
	out, _ := f.srv.awaitEscalation(t.Context(), &gateway.Decision{Decision: "escalate"}, "POST", "https://x.example/y")
	if out != "denied" {
		t.Fatalf("a full approval queue must refuse, got %q", out)
	}
}

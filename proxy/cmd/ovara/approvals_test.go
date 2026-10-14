package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDescribe(t *testing.T) {
	cases := map[string]string{
		"GET https://pypi.org/simple/requests/":                                      "read https://pypi.org/simple/requests/",
		"POST https://api.github.com/repos/o/r/pulls":                                "send data to https://api.github.com/repos/o/r/pulls",
		"DELETE https://api.github.com/repos/o/r/git/refs/heads/x":                   "DELETE https://api.github.com/repos/o/r/git/refs/heads/x",
		"POST https://github.com/org/repo.git/git-receive-pack refs/heads/main":      "push to refs/heads/main on github.com/org/repo",
		"POST https://github.com/org/repo.git/git-receive-pack":                      "push code on github.com/org/repo",
		"POST https://github.com/o/r.git/git-receive-pack refs/heads/a,refs/tags/v1": "push to refs/heads/a, refs/tags/v1 on github.com/o/r",
		"weird": "weird",
		"POST https://github.com/octocat/Hello-World.git/git-upload-pack":     "fetch code from github.com/octocat/Hello-World",
		"GET https://github.com:443/o/r.git/info/refs":                        "look up branches of github.com/o/r",
		"CONNECT UNAUTH github.com:443":                                       "connect to github.com without the agent's proxy token (refused; git and curl retry with it automatically)",
		"GET https://example.com:443/":                                        "read https://example.com/",
		"POST https://httpbin.org:443/post":                                   "send data to https://httpbin.org/post",
		"GET http://localhost:8080/x":                                         "read http://localhost:8080/x",
		"POST https://github.com:443/o/r.git/git-receive-pack refs/heads/dev": "push to refs/heads/dev on github.com/o/r",
	}
	for in, want := range cases {
		if got := describe(in); got != want {
			t.Errorf("describe(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeGateway serves the three approval endpoints the CLI uses.
type fakeGateway struct {
	mu       sync.Mutex
	pending  []pendingApproval
	resolved map[string]string // id → "approve"|"deny"
	by       map[string]string // id → "resolved_by|reason", when the test wants it
	token    string
}

func (f *fakeGateway) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+f.token {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/approval/pending", auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var open []pendingApproval
		for _, a := range f.pending {
			if _, done := f.resolved[a.ApprovalID]; !done {
				open = append(open, a)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"approvals": open, "count": len(open)})
	}))
	resolve := func(verb string) http.HandlerFunc {
		return auth(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			defer f.mu.Unlock()
			f.resolved[r.PathValue("id")] = verb
			if f.by != nil {
				f.by[r.PathValue("id")] = body["resolved_by"] + "|" + body["reason"]
			}
			w.Write([]byte("{}"))
		})
	}
	mux.HandleFunc("POST /v1/approval/{id}/approve", resolve("approve"))
	mux.HandleFunc("POST /v1/approval/{id}/deny", resolve("deny"))
	return mux
}

func newFake(t *testing.T, pend ...pendingApproval) (*fakeGateway, *adminClient) {
	t.Helper()
	f := &fakeGateway{pending: pend, resolved: map[string]string{}, token: "tok"}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, &adminClient{base: srv.URL, token: "tok", hc: srv.Client()}
}

func TestAdminClient_ListApproveDeny(t *testing.T) {
	f, c := newFake(t,
		pendingApproval{ApprovalID: "a1", Resource: "POST https://api.github.com/x"},
		pendingApproval{ApprovalID: "a2", Resource: "DELETE https://api.github.com/y"})

	list, err := c.pending()
	if err != nil || len(list) != 2 {
		t.Fatalf("pending = %v, %v", list, err)
	}
	if err := c.resolve("a1", true, "me", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.resolve("a2", false, "me", "nope"); err != nil {
		t.Fatal(err)
	}
	if f.resolved["a1"] != "approve" || f.resolved["a2"] != "deny" {
		t.Fatalf("resolved = %v", f.resolved)
	}
	if list, _ := c.pending(); len(list) != 0 {
		t.Fatalf("still pending: %v", list)
	}
}

func TestAdminClient_BadTokenSurfacesError(t *testing.T) {
	_, c := newFake(t)
	c.token = "wrong"
	if _, err := c.pending(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
}

func TestAdminClient_GatewayDownIsFriendly(t *testing.T) {
	c := &adminClient{base: "http://127.0.0.1:1", token: "t", hc: &http.Client{Timeout: time.Second}}
	_, err := c.pending()
	if err == nil || !strings.Contains(err.Error(), "ovara run") {
		t.Fatalf("error should tell the user to start ovara run, got %v", err)
	}
}

func TestNewAdminClient_ReadsConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"server_port":"8123","listen_addr":"127.0.0.1","operator_tokens":["optok"]}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := newAdminClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.base != "http://127.0.0.1:8123" || c.token != "optok" {
		t.Fatalf("client = %+v", c)
	}
	if _, err := newAdminClient(t.TempDir()); err == nil {
		t.Fatal("missing config.json must error")
	}
}

// typist answers `ovara watch` the way a person does: each answer is typed
// after its prompt is on screen. When the answers run out the input ends.
type typist struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	answers []string
	w       *io.PipeWriter
}

func newTypist(t *testing.T, answers ...string) (io.Reader, *typist) {
	t.Helper()
	old := typeAheadGrace
	typeAheadGrace = 20 * time.Millisecond
	t.Cleanup(func() { typeAheadGrace = old })
	r, w := io.Pipe()
	return r, &typist{answers: answers, w: w}
}

func (p *typist) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf.Write(b)
	if bytes.Contains(b, []byte("[a]pprove")) {
		if len(p.answers) == 0 {
			p.w.Close()
		} else {
			ans := p.answers[0]
			p.answers = p.answers[1:]
			time.AfterFunc(2*typeAheadGrace, func() { _, _ = p.w.Write([]byte(ans + "\n")) })
		}
	}
	return len(b), nil
}

func (p *typist) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

// Keys typed before a request is on screen do not answer it: a double
// "a⏎" or a paste must not approve the next request unseen.
func TestWatchLoop_IgnoresTypeAhead(t *testing.T) {
	f, c := newFake(t,
		pendingApproval{ApprovalID: "a1", Resource: "POST https://api.github.com/x"},
		pendingApproval{ApprovalID: "a2", Resource: "POST https://attacker.example/y"})
	old := typeAheadGrace
	typeAheadGrace = 20 * time.Millisecond
	defer func() { typeAheadGrace = old }()
	r, w := io.Pipe()
	// "a" twice, already waiting before anything is shown; then, once the
	// first prompt is up, "d"; the second request gets no answer of its own
	in := io.MultiReader(strings.NewReader("a\na\n"), r)
	out := &typist{answers: []string{"d"}, w: w}
	stop := make(chan struct{})
	time.AfterFunc(400*time.Millisecond, func() { close(stop); w.Close() })
	if err := watchLoop(c, in, out, 10*time.Millisecond, stop); err != nil {
		t.Fatal(err)
	}
	if f.resolved["a1"] != "deny" {
		t.Fatalf("a1 = %q, want the answer typed after it was shown (deny)\n%s", f.resolved["a1"], out.String())
	}
	if v, ok := f.resolved["a2"]; ok {
		t.Fatalf("a2 was answered (%s) by keys typed before it was shown", v)
	}
	if !strings.Contains(out.String(), "ignored 2 line(s) typed before") {
		t.Fatalf("the person is not told their early keys were ignored:\n%s", out.String())
	}
}

func TestWatchLoop_ApproveDenySkip(t *testing.T) {
	f, c := newFake(t,
		pendingApproval{ApprovalID: "a1", Resource: "POST https://api.github.com/x"},
		pendingApproval{ApprovalID: "a2", Resource: "DELETE https://api.github.com/y"},
		pendingApproval{ApprovalID: "a3", Resource: "PUT https://example.com/z"})

	// a → approve a1, bogus answer re-asks, d → deny a2, s → skip a3.
	in, out := newTypist(t, "a", "what", "d", "s")
	stop := make(chan struct{})
	time.AfterFunc(500*time.Millisecond, func() { close(stop) })
	if err := watchLoop(c, in, out, 10*time.Millisecond, stop); err != nil {
		t.Fatal(err)
	}
	if f.resolved["a1"] != "approve" || f.resolved["a2"] != "deny" {
		t.Fatalf("resolved = %v\n%s", f.resolved, out.String())
	}
	if _, ok := f.resolved["a3"]; ok {
		t.Fatal("skipped approval must stay pending")
	}
	if !strings.Contains(out.String(), "agent wants to: send data to https://api.github.com/x") {
		t.Fatalf("output lacks plain-English line:\n%s", out.String())
	}
}

func TestBoundarySubnet(t *testing.T) {
	for _, n := range []string{"agent0", "a", "some-long-namespace-name"} {
		idx := boundarySubnetIdx(n)
		if idx < 1 || idx > 250 {
			t.Fatalf("idx(%q) = %d, outside 1..250", n, idx)
		}
		if boundarySubnetIdx(n) != idx {
			t.Fatal("must be stable")
		}
	}
	if boundaryProxyIP(7) != "10.200.7.1" {
		t.Fatalf("got %s", boundaryProxyIP(7))
	}
}

// The keys the proxy adds about a request's body and headers are shown
// with labels a person understands.
func TestContextLines_BodyAndHeaders(t *testing.T) {
	a := sanitizeApproval(pendingApproval{Resource: "POST https://x.example/y", Context: map[string]string{
		"body_note":   "gzip-encoded, cannot preview",
		"body_sha256": "ab12",
		"headers":     "X-Data (40 bytes)",
		"command":     "rm -r -f /work",
	}})
	text := strings.Join(contextLines(a), "\n")
	for _, want := range []string{"⚠ not shown: gzip-encoded", "body sha256: ab12", "headers: X-Data", "command as run: rm -r -f /work"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

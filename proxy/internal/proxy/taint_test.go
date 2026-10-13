package proxy

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// taintServer is an action server whose upstream paths under /issues/ are
// untrusted reads.
func taintServer(t *testing.T) (*Server, *actionGateway, string, *recorder) {
	t.Helper()
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetTaint(true, 0, []string{"http://127.0.0.1:*/repos/*/issues*"}, nil)
	return srv, ag, chainFile, up
}

// ASI01: after the agent reads an issue (content anyone can write), a
// write policy would allow on its own is asked about, with where the
// untrusted content came from and how long ago in front of the person;
// refused, it never reaches upstream, and the receipt says why.
func TestTaint_UntrustedReadThenAllowedWriteAsks(t *testing.T) {
	srv, ag, chainFile, up := taintServer(t)
	ag.setDecision("taint.write", "deny")

	if rec := send(srv, "POST", up.URL+"/before", "text/plain", strings.NewReader("x"), nil); rec.Code != 200 {
		t.Fatalf("write before any untrusted read: %d", rec.Code)
	}
	if rec := send(srv, "GET", up.URL+"/repos/o/r/issues/7", "", nil, nil); rec.Code != 200 {
		t.Fatalf("issue read: %d", rec.Code)
	}
	if r := lastReceiptOf(t, chainFile); !hasReason(r.Reasons, "untrusted_read") {
		t.Fatalf("read receipt reasons %v", r.Reasons)
	}
	hits := up.hits.Load()
	rec := send(srv, "POST", up.URL+"/after", "text/plain", strings.NewReader("x"), nil)
	if rec.Code != http.StatusForbidden || up.hits.Load() != hits {
		t.Fatalf("tainted write: %d hits %d->%d", rec.Code, hits, up.hits.Load())
	}
	q := ag.of("taint.write")
	if len(q) != 1 || q[0].Resource != "taint:POST "+up.URL+"/after" {
		t.Fatalf("questions %+v", q)
	}
	if !strings.Contains(q[0].Context["taint"], "/repos/o/r/issues/7") || !strings.Contains(q[0].Context["taint"], " ago") {
		t.Fatalf("taint context %q", q[0].Context["taint"])
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != "deny" || !hasReasonPrefix(r.Reasons, "tainted_by:") {
		t.Fatalf("receipt %+v", r)
	}
	// Approved, the same write goes out.
	ag.setDecision("taint.write", "escalate")
	ag.status.Store("approved")
	if rec := send(srv, "POST", up.URL+"/after", "text/plain", strings.NewReader("x"), nil); rec.Code != 200 {
		t.Fatalf("approved tainted write: %d", rec.Code)
	}
}

func hasReason(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

func hasReasonPrefix(rs []string, p string) bool {
	for _, r := range rs {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}

// ASI01: the mark lasts the window, then writes go through unasked again.
func TestTaint_WindowExpires(t *testing.T) {
	srv, ag, _, up := taintServer(t)
	srv.SetTaint(true, 10*time.Minute, []string{"http://127.0.0.1:*/repos/*/issues*"}, nil)
	var mu sync.Mutex
	now := time.Now()
	srv.taint.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ag.setDecision("taint.write", "deny")
	send(srv, "GET", up.URL+"/repos/o/r/issues", "", nil, nil)
	mu.Lock()
	now = now.Add(9 * time.Minute)
	mu.Unlock()
	if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("inside the window: %d", rec.Code)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), nil); rec.Code != 200 {
		t.Fatalf("after the window: %d", rec.Code)
	}
	if n := len(ag.of("taint.write")); n != 1 {
		t.Fatalf("asked %d times", n)
	}
}

// ASI01: a read a person approved (the host is not trusted for reads), a
// read allowed by a "trust this host" rule, and a model request whose
// provider-side fetch was let through all taint the agent.
func TestTaint_ApprovedReadsTrustedHostsAndModelFetchesTaint(t *testing.T) {
	t.Run("approved read", func(t *testing.T) {
		srv, ag, _, up := taintServer(t)
		ag.setDecision("taint.write", "deny")
		ag.urlDecision.Store("escalate")
		ag.status.Store("approved")
		if rec := send(srv, "GET", up.URL+"/page", "", nil, nil); rec.Code != 200 {
			t.Fatalf("approved read: %d", rec.Code)
		}
		ag.urlDecision.Store("allow")
		if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), nil); rec.Code != http.StatusForbidden {
			t.Fatalf("write after an approved read: %d", rec.Code)
		}
		if q := ag.of("taint.write"); len(q) != 1 || !strings.Contains(q[0].Context["taint"], "a read a person approved") {
			t.Fatalf("questions %+v", q)
		}
	})
	t.Run("trusted from an approval prompt", func(t *testing.T) {
		srv, ag, _, up := taintServer(t)
		ag.setDecision("taint.write", "deny")
		ag.matchedRule.Store(runTrustRulePrefix + " Reading from 127.0.0.1 (trusted from an approval prompt)")
		send(srv, "GET", up.URL+"/page", "", nil, nil)
		ag.matchedRule.Store("Writes are allowed here")
		if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), nil); rec.Code != http.StatusForbidden {
			t.Fatalf("write after a run-trusted read: %d", rec.Code)
		}
	})
	t.Run("model fetch", func(t *testing.T) {
		srv, ag, _, up := taintServer(t)
		srv.SetModelGate(true, []string{"127.0.0.1"})
		ag.setDecision("taint.write", "deny")
		body := `{"model":"m","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}],"messages":[]}`
		if rec := send(srv, "POST", up.URL+"/v1/messages", "application/json", strings.NewReader(body), nil); rec.Code != 200 {
			t.Fatalf("allowed model fetch: %d %s", rec.Code, rec.Body)
		}
		// Another host: localhost is not a model host.
		other := strings.Replace(up.URL, "127.0.0.1", "localhost", 1)
		if rec := send(srv, "POST", other+"/w", "", strings.NewReader("x"), nil); rec.Code != http.StatusForbidden {
			t.Fatalf("write after a model fetch: %d", rec.Code)
		}
	})
}

// ASI01: what the rule does not touch: writes policy already asks about
// (one question, not two), calls to the model, git fetches, and other
// agents.
func TestTaint_LeavesOtherDecisionsAlone(t *testing.T) {
	srv, ag, _, up := taintServer(t)
	srv.SetModelGate(true, []string{"localhost"})
	srv.SetAgents(map[string]string{"alpha": tokAlpha, "beta": tokBeta})
	ag.setDecision("taint.write", "deny")
	send(srv, "GET", up.URL+"/repos/o/r/issues/1", "", nil, asAgent(tokAlpha))

	// another agent is not tainted
	if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("other agent's write: %d", rec.Code)
	}
	// the model API
	model := strings.Replace(up.URL, "127.0.0.1", "localhost", 1)
	if rec := send(srv, "POST", model+"/v1/messages", "application/json", strings.NewReader(`{"messages":[]}`), asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("model call while tainted: %d", rec.Code)
	}
	// a git fetch
	fetch := pkt("command=ls-refs\n") + "0000"
	if rec := send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", "application/x-git-upload-pack-request", strings.NewReader(fetch), asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("git fetch while tainted: %d %s", rec.Code, rec.Body)
	}
	if n := len(ag.of("taint.write")); n != 0 {
		t.Fatalf("asked %d times", n)
	}
	// a write policy escalates: one approval (the URL's), no taint question
	ag.urlDecision.Store("escalate")
	ag.status.Store("approved")
	if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("escalated write: %d", rec.Code)
	}
	if n := len(ag.of("taint.write")); n != 0 || ag.creates.Load() != 1 {
		t.Fatalf("taint questions %d, approvals %d", n, ag.creates.Load())
	}
}

// ASI01: a git push that ref rules allow is a write like any other.
func TestTaint_AllowedPushAsks(t *testing.T) {
	srv, ag, _, up := taintServer(t)
	ag.setDecision("taint.write", "deny")
	send(srv, "GET", up.URL+"/repos/o/r/issues/1", "", nil, nil)
	push := pkt(shaA+" "+shaB+" refs/heads/feature\x00report-status\n") + "0000PACK"
	rec := send(srv, "POST", up.URL+"/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(push), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("push while tainted: %d", rec.Code)
	}
	if q := ag.of("taint.write"); len(q) != 1 || !strings.HasSuffix(q[0].Resource, "git-receive-pack refs/heads/feature") {
		t.Fatalf("questions %+v", q)
	}
}

// The rule can be turned off.
func TestTaint_Off(t *testing.T) {
	srv, ag, _, up := taintServer(t)
	srv.SetTaint(false, 0, nil, nil)
	ag.setDecision("taint.write", "deny")
	send(srv, "GET", up.URL+"/repos/o/r/issues/1", "", nil, nil)
	if rec := send(srv, "POST", up.URL+"/w", "", strings.NewReader("x"), nil); rec.Code != 200 {
		t.Fatalf("taint off: %d", rec.Code)
	}
}

// The default untrusted-content patterns cover GitHub and GitLab issues,
// pull request comments and discussions, by API and on the web, however
// the path is spelt, and not ordinary code reads.
func TestDefaultUntrustedReadPatterns(t *testing.T) {
	yes := []string{
		"https://api.github.com/repos/o/r/issues",
		"https://api.github.com/repos/o/r/issues/12/comments",
		"https://api.github.com:443/repos/o/r/%69ssues/1",
		"https://api.github.com//repos/o/r/issues/1",
		"https://API.GITHUB.COM/repos/o/r/issues/1",
		"https://api.github.com/repos/o/r/pulls/3/comments",
		"https://api.github.com/repos/o/r/discussions/4",
		"https://github.com/o/r/issues/5",
		"https://github.com/o/r/pull/6",
		"https://gitlab.com/api/v4/projects/9/issues/1/notes",
		"https://gitlab.com/api/v4/projects/9/merge_requests/2/notes",
		"https://gitlab.com/g/p/-/issues/3",
	}
	no := []string{
		"https://api.github.com/repos/o/r/contents/README.md",
		"https://api.github.com/repos/o/r/pulls/3/files",
		"https://github.com/o/r/blob/main/x.go",
		"https://raw.githubusercontent.com/o/r/main/issues.md",
	}
	for _, u := range yes {
		r, _ := http.NewRequest("GET", u, nil)
		if !matchAny(defaultUntrustedReads, matchURL(r)) {
			t.Errorf("%s should be an untrusted read (%s)", u, matchURL(r))
		}
	}
	for _, u := range no {
		r, _ := http.NewRequest("GET", u, nil)
		if matchAny(defaultUntrustedReads, matchURL(r)) {
			t.Errorf("%s should not be an untrusted read", u)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"a*c", "abc", true}, {"a*c", "ac", true}, {"a*c", "a/b/c", true}, {"a*c", "abd", false},
		{"*", "", true}, {"a*b*c", "axxbyyc", true}, {"a*b*c", "axxbyy", false}, {"abc", "abcd", false},
	}
	for _, c := range cases {
		if got := globMatch(c.p, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

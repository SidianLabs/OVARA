package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

const openReadRule = "[profile balanced] [open read] Reading from any public host is allowed"

// the recorder by another name: a second host for the same upstream
func localhostURL(t *testing.T, recorderURL, path string) string {
	t.Helper()
	u, err := url.Parse(recorderURL)
	if err != nil {
		t.Fatal(err)
	}
	return "http://localhost:" + u.Port() + path
}

// Under an open-read rule the distinct unlisted hosts an agent reads are
// capped; past the cap each further host asks once, and an approval
// admits it for the rest of the run.
func TestOpenReadsAskPastTheHostCap(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	ag.matchedRule.Store(openReadRule)
	srv.SetOpenReads(true, 1)
	ag.setDecision(actionOpenHosts, "deny")
	for _, p := range []string{"/a", "/b"} {
		if rec := send(srv, "GET", up.URL+p, "", nil, nil); rec.Code != 200 {
			t.Fatalf("the first host, %s: %d", p, rec.Code)
		}
	}
	// a second host is one past the cap: asked, refused, never dialled
	other := localhostURL(t, up.URL, "/x")
	rec := send(srv, "GET", other, "", nil, nil)
	q := ag.of(actionOpenHosts)
	if rec.Code != http.StatusForbidden || len(q) != 1 || q[0].Resource != "host:localhost" || q[0].Context["cap"] != "1" {
		t.Fatalf("past the cap: %d, questions %+v", rec.Code, q)
	}
	if up.hits.Load() != 2 {
		t.Fatalf("the refused host was dialled: hits=%d", up.hits.Load())
	}
	// approved: admitted for the rest of the run, asked once
	ag.setDecision(actionOpenHosts, "escalate")
	ag.status.Store("approved")
	if rec := send(srv, "GET", other, "", nil, nil); rec.Code != 200 {
		t.Fatalf("approved host: %d", rec.Code)
	}
	if rec := send(srv, "GET", other+"?again", "", nil, nil); rec.Code != 200 || ag.creates.Load() != 1 {
		t.Fatalf("admitted host asked again: %d, approvals %d", rec.Code, ag.creates.Load())
	}
}

// Reads a rule names (the trusted list, a preset, a host trusted for the
// run) are not open reads and never count; nor is anything but a GET or
// HEAD the policy allowed.
func TestOpenReadsCountOnlyCatchAllReads(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetOpenReads(true, 1)
	ag.setDecision(actionOpenHosts, "deny")
	ag.matchedRule.Store("Reading from pypi.org is allowed")
	for _, u := range []string{up.URL + "/a", localhostURL(t, up.URL, "/b")} {
		if rec := send(srv, "GET", u, "", nil, nil); rec.Code != 200 {
			t.Fatalf("%s: %d", u, rec.Code)
		}
	}
	if n := len(ag.of(actionOpenHosts)); n != 0 {
		t.Fatalf("asked %d times about reads a rule names", n)
	}
	if !isOpenRead(openReadRule, gwAllow, "GET") || !isOpenRead(openReadRule, gwAllow, "HEAD") ||
		isOpenRead(openReadRule, gwAllow, "POST") || isOpenRead(openReadRule, gwEscalate, "GET") || isOpenRead("writes need approval", gwAllow, "GET") {
		t.Fatal("isOpenRead")
	}
	srv.SetOpenReads(false, 0)
	if out, _ := srv.checkOpenHosts(t.Context(), "anything.example"); out != pkgAllow {
		t.Fatalf("off: %s", out)
	}
}

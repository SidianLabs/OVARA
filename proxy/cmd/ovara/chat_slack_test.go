package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.proxy/internal/config"
)

// fakeSlack is the two Web API methods the bridge uses.
type fakeSlack struct {
	mu      sync.Mutex
	posts   []slackPost           // every chat.postMessage, in order
	replies map[string][]slackMsg // thread ts → the replies in it
	next    int
	token   string
}

type slackPost struct{ Channel, Text, ThreadTS, TS string }

func (f *fakeSlack) stamp() string { f.next++; return fmt.Sprintf("1700000000.%06d", f.next) }

func (f *fakeSlack) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /chat.postMessage", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
			return
		}
		var body struct {
			Channel, Text string
			ThreadTS      string `json:"thread_ts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		ts := f.stamp()
		f.posts = append(f.posts, slackPost{body.Channel, body.Text, body.ThreadTS, ts})
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": ts})
	})
	mux.HandleFunc("GET /conversations.replies", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ts, oldest := r.URL.Query().Get("ts"), r.URL.Query().Get("oldest")
		msgs := []slackMsg{{TS: ts, User: "UBOT", BotID: "B1", Text: "the parent"}}
		for _, m := range f.replies[ts] {
			if oldest == "" || m.TS > oldest {
				msgs = append(msgs, m)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "messages": msgs})
	})
	return mux
}

// say adds a reply to the thread that shows approval id.
func (f *fakeSlack) say(t *testing.T, id, user, text string) {
	t.Helper()
	ts := f.threadOf(id)
	if ts == "" {
		t.Fatalf("no thread for %s", id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replies == nil {
		f.replies = map[string][]slackMsg{}
	}
	f.replies[ts] = append(f.replies[ts], slackMsg{TS: f.stamp(), User: user, Text: text})
}

func (f *fakeSlack) threadOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.posts {
		if p.ThreadTS == "" && strings.Contains(p.Text, "id: "+id) {
			return p.TS
		}
	}
	return ""
}

// inThread is what was posted into approval id's thread.
func (f *fakeSlack) inThread(id string) []string {
	ts := f.threadOf(id)
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, p := range f.posts {
		if p.ThreadTS == ts && ts != "" {
			out = append(out, p.Text)
		}
	}
	return out
}

func (f *fakeSlack) topLevel() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.posts {
		if p.ThreadTS == "" {
			n++
		}
	}
	return n
}

func newSlackTest(t *testing.T, allowed []string, pend ...pendingApproval) (*fakeGateway, *fakeSlack, *slackBridge, *[]string) {
	t.Helper()
	gw, admin := newFake(t, pend...)
	gw.by = map[string]string{}
	fs := &fakeSlack{token: "xoxb-test"}
	srv := httptest.NewServer(fs.handler())
	t.Cleanup(srv.Close)
	set := map[string]bool{}
	for _, u := range allowed {
		set[u] = true
	}
	var logged []string
	b := &slackBridge{admin: admin, hc: srv.Client(), api: srv.URL, token: "xoxb-test", channel: "C0TEST", allowed: set,
		every: time.Second, logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) },
		threads: map[string]*slackThread{}, done: map[string]bool{}}
	return gw, fs, b, &logged
}

func approvalAt(id, resource string) pendingApproval {
	return pendingApproval{ApprovalID: id, ActionType: actionHTTPRequest, Resource: resource, CreatedAt: time.Now()}
}

func TestSlackBridge_PostsOnceAndAnAllowedReplyDecides(t *testing.T) {
	gw, fs, b, _ := newSlackTest(t, []string{"U1"},
		approvalAt("apr_1", "POST https://api.github.com:443/repos/o/r/pulls"),
		pendingApproval{ApprovalID: "apr_2", ActionType: actionShell, Resource: "shell:git push", CreatedAt: time.Now()})
	b.tick()
	b.tick()
	if n := fs.topLevel(); n != 2 {
		t.Fatalf("posted %d top-level messages, want one per request", n)
	}
	first := fs.posts[0].Text
	for _, want := range []string{"Approval needed", "api.github.com", "id: apr_1", "*approve*", "C0TEST"} {
		if !strings.Contains(first, want) && !(want == "C0TEST" && fs.posts[0].Channel == want) {
			t.Errorf("the post lacks %q:\n%s", want, first)
		}
	}
	fs.say(t, "apr_1", "U1", "approve: looks fine")
	b.tick()
	if gw.resolved["apr_1"] != verdictApprove || gw.by["apr_1"] != "slack:U1|looks fine" {
		t.Fatalf("apr_1: %q by %q", gw.resolved["apr_1"], gw.by["apr_1"])
	}
	if gw.resolved["apr_2"] != "" {
		t.Fatal("apr_2 was decided by a reply in another thread")
	}
	if got := fs.inThread("apr_1"); len(got) != 1 || !strings.Contains(got[0], "approved by <@U1>: looks fine") {
		t.Fatalf("thread apr_1: %q", got)
	}
	fs.say(t, "apr_2", "U1", "Deny")
	b.tick()
	if gw.resolved["apr_2"] != verdictDeny || gw.by["apr_2"] != "slack:U1|" {
		t.Fatalf("apr_2: %q by %q", gw.resolved["apr_2"], gw.by["apr_2"])
	}
	if got := fs.inThread("apr_2"); len(got) != 1 || !strings.Contains(got[0], "denied by <@U1>") {
		t.Fatalf("thread apr_2: %q", got)
	}
	// decided threads are not read again, and nothing is posted twice
	b.tick()
	if len(b.threads) != 0 || fs.topLevel() != 2 {
		t.Fatalf("threads %d, top-level %d", len(b.threads), fs.topLevel())
	}
}

func TestSlackBridge_OnlyAllowedPeopleDecide(t *testing.T) {
	gw, fs, b, _ := newSlackTest(t, []string{"U1"}, approvalAt("apr_1", "POST https://httpbin.org:443/anything"))
	b.tick()
	fs.say(t, "apr_1", "U9", "approve")
	b.tick()
	fs.say(t, "apr_1", "U9", "approve!!")
	b.tick()
	if gw.resolved["apr_1"] != "" {
		t.Fatal("someone not in allowed_users decided")
	}
	if got := fs.inThread("apr_1"); len(got) != 1 || !strings.Contains(got[0], "<@U9> only the people listed") {
		t.Fatalf("one warning expected: %q", got)
	}
	// a bot saying approve, and talk in the thread, change nothing
	fs.mu.Lock()
	ts := fs.threadOf2("apr_1")
	fs.replies[ts] = append(fs.replies[ts], slackMsg{TS: fs.stamp(), User: "UB", BotID: "B9", Text: "approve"}, slackMsg{TS: fs.stamp(), User: "U1", Text: "what is this request?"})
	fs.mu.Unlock()
	b.tick()
	if gw.resolved["apr_1"] != "" {
		t.Fatal("a bot or talk decided")
	}
	fs.say(t, "apr_1", "U1", "deny: not from CI")
	b.tick()
	if gw.resolved["apr_1"] != verdictDeny || gw.by["apr_1"] != "slack:U1|not from CI" {
		t.Fatalf("apr_1: %q by %q", gw.resolved["apr_1"], gw.by["apr_1"])
	}
}

// threadOf2 is threadOf for a caller already holding the lock.
func (f *fakeSlack) threadOf2(id string) string {
	for _, p := range f.posts {
		if p.ThreadTS == "" && strings.Contains(p.Text, "id: "+id) {
			return p.TS
		}
	}
	return ""
}

func TestSlackBridge_StopNotesOpenThreads(t *testing.T) {
	_, fs, b, _ := newSlackTest(t, []string{"U1"}, approvalAt("apr_1", "POST https://httpbin.org:443/anything"))
	b.every = time.Hour
	stop := b.start()
	for i := 0; i < 50 && fs.topLevel() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	if got := fs.inThread("apr_1"); len(got) != 1 || !strings.Contains(got[0], "ovara run stopped") {
		t.Fatalf("thread after stop: %q", got)
	}
	if len(b.threads) != 0 {
		t.Fatal("threads kept after stop")
	}
}

func TestSlackBridge_NoAllowedUsersMeansNotifyOnly(t *testing.T) {
	gw, fs, b, _ := newSlackTest(t, nil, approvalAt("apr_9", "POST https://httpbin.org:443/anything"))
	if !strings.Contains(b.describe(), "cannot decide") {
		t.Fatal(b.describe())
	}
	b.tick()
	fs.say(t, "apr_9", "U1", "approve")
	b.tick()
	if gw.resolved["apr_9"] != "" {
		t.Fatal("decided with nobody allowed")
	}
}

func TestSlackBridge_EndedElsewhereIsNoted(t *testing.T) {
	gw, fs, b, _ := newSlackTest(t, []string{"U1"}, approvalAt("apr_1", "POST https://httpbin.org:443/anything"))
	b.tick()
	gw.mu.Lock()
	gw.resolved["apr_1"] = verdictDeny // ovara deny, the page, a timeout
	gw.mu.Unlock()
	b.tick()
	if got := fs.inThread("apr_1"); len(got) != 1 || !strings.Contains(got[0], "ended without an answer here") {
		t.Fatalf("thread: %q", got)
	}
	b.tick()
	if len(b.threads) != 0 || fs.topLevel() != 1 || len(fs.inThread("apr_1")) != 1 {
		t.Fatal("a closed request was posted or noted again")
	}
}

func TestSlackBridge_TextIsEscapedAndErrorsAreReportedOnce(t *testing.T) {
	_, fs, b, logged := newSlackTest(t, []string{"U1"}, approvalAt("apr_1", "GET https://x.example:443/?a=1&b=<2>"))
	b.tick()
	if txt := fs.posts[0].Text; !strings.Contains(txt, "a=1&amp;b=&lt;2&gt;") || strings.Contains(txt, "<2>") {
		t.Fatalf("not escaped: %s", txt)
	}
	b.token = "wrong"
	fs.say(t, "apr_1", "U1", "approve")
	b.tick()
	b.tick()
	n := 0
	for _, l := range *logged {
		if strings.Contains(l, "invalid_auth") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the same error was logged %d times: %q", n, *logged)
	}
}

func TestSlackDecision(t *testing.T) {
	cases := []struct {
		in      string
		approve bool
		reason  string
		ok      bool
	}{
		{"approve", true, "", true}, {"Approved: fine by me", true, "fine by me", true}, {"deny", false, "", true},
		{"DENIED - not now", false, "not now", true}, {"reject", false, "", true}, {"yes", false, "", false},
		{"approve?", true, "?", true}, {"I would approve this", false, "", false}, {"", false, "", false},
	}
	for _, c := range cases {
		approve, reason, ok := slackDecision(c.in)
		if approve != c.approve || reason != c.reason || ok != c.ok {
			t.Errorf("%q: %v %q %v", c.in, approve, reason, ok)
		}
	}
}

// A route sends approvals of some kinds to another channel, where only the
// people listed for the route decide; everything else stays in the default
// channel with the default people.
func TestSlackBridge_RoutesByActionTypeAndResource(t *testing.T) {
	tunnel := pendingApproval{ApprovalID: "apr_tcp", ActionType: "tcp.connect", Resource: "tcp:db.internal:5432", CreatedAt: time.Now()}
	prod := pendingApproval{ApprovalID: "apr_prod", ActionType: actionHTTPRequest, Resource: "POST https://prod.example.com/deploy", CreatedAt: time.Now()}
	gw, fs, b, _ := newSlackTest(t, []string{"U1"}, approvalAt("apr_http", "POST https://api.example.com/x"), tunnel, prod)
	b.routes = slackRoutes([]config.SlackRoute{
		{Name: "security", ActionTypes: []string{"tcp.connect", "download.file"}, Channel: "C0SEC", AllowedUsers: []string{"U9"}},
		{Name: "production", Resources: []string{"* https://prod.example.com/*"}, Channel: "C0PROD"},
	})
	b.tick()
	where := map[string]string{}
	for _, p := range fs.posts {
		if p.ThreadTS == "" {
			where[p.Text[:20]] = p.Channel
		}
	}
	chanOf := func(id string) string {
		th := b.threads[id]
		if th == nil {
			return "(none)"
		}
		return th.channel
	}
	if chanOf("apr_http") != "C0TEST" || chanOf("apr_tcp") != "C0SEC" || chanOf("apr_prod") != "C0PROD" {
		t.Fatalf("channels: http=%s tcp=%s prod=%s (posts %v)", chanOf("apr_http"), chanOf("apr_tcp"), chanOf("apr_prod"), where)
	}
	// U1 may decide in the default channel but not on the security route.
	fs.say(t, "apr_tcp", "U1", "approve")
	b.tick()
	if gw.by["apr_tcp"] != "" {
		t.Fatalf("a default-channel person decided a routed approval")
	}
	if replies := fs.inThread("apr_tcp"); len(replies) == 0 || !strings.Contains(replies[len(replies)-1], "route security") {
		t.Fatalf("U1 was not told which people decide: %v", replies)
	}
	fs.say(t, "apr_tcp", "U9", "approve: known database")
	b.tick()
	if !strings.HasPrefix(gw.by["apr_tcp"], "slack:U9") {
		t.Fatalf("the route's person did not decide: %v", gw.by)
	}
	// The production route lists nobody: told, cannot decide.
	fs.say(t, "apr_prod", "U1", "approve")
	fs.say(t, "apr_prod", "U9", "approve")
	b.tick()
	if gw.by["apr_prod"] != "" {
		t.Fatalf("a route with no people decided: %v", gw.by)
	}
	// The default channel still works for the rest.
	fs.say(t, "apr_http", "U1", "deny: not now")
	b.tick()
	if !strings.HasPrefix(gw.by["apr_http"], "slack:U1") {
		t.Fatalf("default channel: %v", gw.by)
	}
}

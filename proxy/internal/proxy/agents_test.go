package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
)

var (
	agentAlpha = "alpha"
	tokAlpha   = strings.Repeat("a1", 32)
	tokBeta    = strings.Repeat("b2", 32)
	tokLegacy  = strings.Repeat("c3", 32)
)

func asAgent(tok string) map[string]string {
	return map[string]string{"Proxy-Authorization": "Bearer " + tok}
}

// ASI03/ASI07: every named agent's token is accepted, the legacy
// agent_token still is, anything else is not; receipts carry the agent's
// name (the legacy token keeps its hash label) and the gateway is told
// which agent asks, so an approval can say so.
func TestNamedAgentsAreAcceptedAndNamed(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetClientAuth(tokLegacy)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "beta": tokBeta})

	if rec := send(srv, "GET", up.URL+"/a", "", nil, asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("alpha: %d", rec.Code)
	}
	if got := lastReceiptOf(t, chainFile).Agent; got != agentAlpha {
		t.Fatalf("receipt agent %q, want alpha", got)
	}
	if c := ag.all(); c[len(c)-1].Context["agent"] != agentAlpha {
		t.Fatalf("gateway not told the agent: %+v", c[len(c)-1].Context)
	}
	if rec := send(srv, "GET", up.URL+"/b", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("beta: %d", rec.Code)
	}
	if got := lastReceiptOf(t, chainFile).Agent; got != "beta" {
		t.Fatalf("receipt agent %q, want beta", got)
	}
	if rec := send(srv, "GET", up.URL+"/c", "", nil, asAgent(tokLegacy)); rec.Code != 200 {
		t.Fatalf("legacy token: %d", rec.Code)
	}
	if got := lastReceiptOf(t, chainFile).Agent; got != agentLabel(tokLegacy) {
		t.Fatalf("legacy receipt agent %q, want %q", got, agentLabel(tokLegacy))
	}
	if c := ag.all(); c[len(c)-1].Context["agent"] != config.DefaultAgentName {
		t.Fatalf("legacy agent not named %q: %+v", config.DefaultAgentName, c[len(c)-1].Context)
	}
	for _, bad := range []string{"", tokAlpha[:len(tokAlpha)-1], tokAlpha + "x", "nope"} {
		h := map[string]string{}
		if bad != "" {
			h = asAgent(bad)
		}
		if rec := send(srv, "GET", up.URL+"/d", "", nil, h); rec.Code != http.StatusProxyAuthRequired {
			t.Fatalf("token %q: %d", bad, rec.Code)
		}
	}
	if up.hits.Load() != 3 {
		t.Fatalf("hits %d", up.hits.Load())
	}
}

// ASI03: named agents alone turn client authentication on.
func TestNamedAgentsAloneRequireAuth(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha})
	if rec := send(srv, "GET", up.URL+"/a", "", nil, nil); rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := send(srv, "GET", up.URL+"/a", "", nil, asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("alpha: %d", rec.Code)
	}
}

func watchFiles(t *testing.T, srv *Server, agents map[string]string) (proxyJSON, revoked string) {
	t.Helper()
	dir := t.TempDir()
	proxyJSON = filepath.Join(dir, "proxy.json")
	doc := map[string]any{"gateway_url": "http://127.0.0.1:1", "agents": agents}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(proxyJSON, b, 0o600); err != nil {
		t.Fatal(err)
	}
	revoked = filepath.Join(dir, "var", "revoked_agents.json")
	stop := srv.WatchAgentFiles(proxyJSON, revoked, 20*time.Millisecond)
	t.Cleanup(stop)
	return proxyJSON, revoked
}

func stopAgents(t *testing.T, path string, names ...string) {
	t.Helper()
	rv := &config.RevokedAgents{Stopped: map[string]time.Time{}}
	for _, n := range names {
		rv.Stopped[n] = time.Now()
	}
	if err := rv.Save(path); err != nil {
		t.Fatal(err)
	}
}

// waitCode sends until the answer is want or a second has passed.
func waitCode(t *testing.T, srv *Server, url, tok string, want int) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		rec := send(srv, "GET", url, "", nil, asAgent(tok))
		if rec.Code == want {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %d after a second, want %d: %s", rec.Code, want, rec.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ASI10: `ovara kill` stops one agent within a second: its requests get
// 403 "stopped by its operator" with a receipt, other agents go on, and
// restoring it lets it back in.
func TestKilledAgentIsRefusedWithinASecond(t *testing.T) {
	srv, _, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	_, revoked := watchFiles(t, srv, map[string]string{agentAlpha: tokAlpha, "beta": tokBeta})
	waitCode(t, srv, up.URL+"/a", tokAlpha, 200)

	stopAgents(t, revoked, agentAlpha)
	rec := waitCode(t, srv, up.URL+"/a", tokAlpha, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), agentStoppedMessage) {
		t.Fatalf("body %s", rec.Body)
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != gwDeny || r.Agent != agentAlpha || len(r.Reasons) != 1 || r.Reasons[0] != "agent_stopped" {
		t.Fatalf("receipt %+v", r)
	}
	hits := up.hits.Load()
	if rec := send(srv, "GET", up.URL+"/b", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("beta stopped too: %d", rec.Code)
	}
	if up.hits.Load() != hits+1 {
		t.Fatal("stopped agent reached upstream")
	}
	// A CONNECT from the stopped agent is refused too.
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.Header.Set("Proxy-Authorization", "Bearer "+tokAlpha)
	cr := httptest.NewRecorder()
	srv.ServeHTTP(cr, req)
	if cr.Code != http.StatusForbidden {
		t.Fatalf("CONNECT from stopped agent: %d", cr.Code)
	}

	stopAgents(t, revoked) // ovara agent restore alpha
	waitCode(t, srv, up.URL+"/a", tokAlpha, 200)

	stopAgents(t, revoked, config.AllAgents) // ovara kill without -agent
	waitCode(t, srv, up.URL+"/b", tokBeta, http.StatusForbidden)
}

// ASI10: a tunnel opened before the kill carries no more requests.
func TestKilledAgentsOpenTunnelCarriesNoMore(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha})
	srv.SetStoppedAgents([]string{agentAlpha})
	r := httptest.NewRequest("GET", up.URL+"/x", nil)
	rec := httptest.NewRecorder()
	srv.handleRequest(rec, withAgent(r, agentIdentity{name: agentAlpha, label: agentAlpha}))
	if rec.Code != http.StatusForbidden || up.hits.Load() != 0 {
		t.Fatalf("request in an old tunnel: %d hits=%d", rec.Code, up.hits.Load())
	}
}

// ASI10: a request from the stopped agent that was waiting for a person
// stops waiting.
func TestKilledAgentsWaitingRequestStops(t *testing.T) {
	srv, _, _ := newActionServer(t, "escalate")
	srv.SetEscalateWindow(30*time.Second, 10*time.Millisecond)
	up := newRecorder(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha})
	done := make(chan int, 1)
	go func() { done <- send(srv, "POST", up.URL+"/x", "", strings.NewReader("x"), asAgent(tokAlpha)).Code }()
	time.Sleep(100 * time.Millisecond)
	srv.SetStoppedAgents([]string{agentAlpha})
	select {
	case code := <-done:
		if code != http.StatusForbidden || up.hits.Load() != 0 {
			t.Fatalf("stopped waiting request: %d hits=%d", code, up.hits.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request from a stopped agent kept waiting")
	}
}

// ASI03: agents added to or removed from proxy.json while the proxy runs
// take effect, and a broken edit keeps the agents as they were.
func TestAgentsReloadFromProxyJSON(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	proxyJSON, _ := watchFiles(t, srv, map[string]string{agentAlpha: tokAlpha})
	waitCode(t, srv, up.URL+"/a", tokAlpha, 200)
	if err := config.WriteAgents(proxyJSON, map[string]string{agentAlpha: tokAlpha, "beta": tokBeta}); err != nil {
		t.Fatal(err)
	}
	waitCode(t, srv, up.URL+"/a", tokBeta, 200)
	if err := config.WriteAgents(proxyJSON, map[string]string{"beta": tokBeta}); err != nil {
		t.Fatal(err)
	}
	waitCode(t, srv, up.URL+"/a", tokAlpha, http.StatusProxyAuthRequired)
	if err := os.WriteFile(proxyJSON, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if rec := send(srv, "GET", up.URL+"/a", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("a broken proxy.json dropped the agents: %d", rec.Code)
	}
}

// A revoked-agents file that cannot be read keeps the agent stopped.
func TestBrokenRevokedFileKeepsAgentsStopped(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	_, revoked := watchFiles(t, srv, map[string]string{agentAlpha: tokAlpha})
	stopAgents(t, revoked, agentAlpha)
	waitCode(t, srv, up.URL+"/a", tokAlpha, http.StatusForbidden)
	if err := os.WriteFile(revoked, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if rec := send(srv, "GET", up.URL+"/a", "", nil, asAgent(tokAlpha)); rec.Code != http.StatusForbidden {
		t.Fatalf("broken file let a stopped agent back in: %d", rec.Code)
	}
}

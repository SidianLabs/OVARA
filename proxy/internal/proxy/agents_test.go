package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// ASI03: a proxy whose only client credentials are named agents keeps
// authentication on when the last agent is removed while it runs: it then
// refuses everyone, it never accepts anonymous clients.
func TestRemovingTheLastAgentKeepsAuthOn(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	proxyJSON, _ := watchFiles(t, srv, map[string]string{agentAlpha: tokAlpha})
	waitCode(t, srv, up.URL+"/a", tokAlpha, 200)
	if rec := send(srv, "GET", up.URL+"/a", "", nil, nil); rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("anonymous before: %d", rec.Code)
	}
	if err := config.WriteAgents(proxyJSON, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	waitCode(t, srv, up.URL+"/a", tokAlpha, http.StatusProxyAuthRequired)
	if rec := send(srv, "GET", up.URL+"/a", "", nil, nil); rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("anonymous after removing the last agent: %d", rec.Code)
	}
	hits := up.hits.Load()
	// Adding an agent back lets that agent, and only it, in.
	if err := config.WriteAgents(proxyJSON, map[string]string{"beta": tokBeta}); err != nil {
		t.Fatal(err)
	}
	waitCode(t, srv, up.URL+"/b", tokBeta, 200)
	if rec := send(srv, "GET", up.URL+"/a", "", nil, nil); rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("anonymous after re-adding: %d", rec.Code)
	}
	if up.hits.Load() != hits+1 {
		t.Fatalf("hits %d, want %d", up.hits.Load(), hits+1)
	}
}

// ASI03/ASI10: a tunnel opened by an agent that has since been removed (or
// given a new token) carries no more requests, and the refusal is receipted.
func TestRemovedAgentsOpenTunnelCarriesNoMore(t *testing.T) {
	srv, _, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "beta": tokBeta})
	alpha := agentIdentity{name: agentAlpha, label: agentAlpha, token: tokAlpha}
	inTunnel := func(id agentIdentity) int {
		r := httptest.NewRequest("GET", up.URL+"/x", nil)
		rec := httptest.NewRecorder()
		srv.handleRequest(rec, withAgent(r, id))
		return rec.Code
	}
	if code := inTunnel(alpha); code != 200 {
		t.Fatalf("registered agent in a tunnel: %d", code)
	}
	srv.SetAgents(map[string]string{"beta": tokBeta}) // alpha removed
	if code := inTunnel(alpha); code != http.StatusForbidden {
		t.Fatalf("removed agent's tunnel: %d", code)
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != gwDeny || r.Agent != agentAlpha || len(r.Reasons) != 1 || r.Reasons[0] != "agent_removed" {
		t.Fatalf("receipt %+v", r)
	}
	// The same name with a new token: the old tunnel is still refused.
	srv.SetAgents(map[string]string{agentAlpha: tokLegacy, "beta": tokBeta})
	if code := inTunnel(alpha); code != http.StatusForbidden {
		t.Fatalf("old token's tunnel after a new token: %d", code)
	}
	// An identity without a token (taken while authentication was off) is
	// refused once authentication is on.
	if code := inTunnel(agentIdentity{name: agentAlpha, label: agentAlpha}); code != http.StatusForbidden {
		t.Fatalf("tokenless identity: %d", code)
	}
	if up.hits.Load() != 1 {
		t.Fatalf("hits %d", up.hits.Load())
	}
}

// ASI10: a response still streaming when its agent is stopped or removed
// is cut within about a second, and the cut is receipted.
func TestAgentsStreamingResponseIsCutWhenStoppedOrRemoved(t *testing.T) {
	for _, how := range []string{"stopped", "removed"} {
		t.Run(how, func(t *testing.T) {
			srv, _, chainFile := newActionServer(t, "allow")
			srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "beta": tokBeta})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				for i := 0; i < 100; i++ {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
					_, _ = io.WriteString(w, ": keep-alive\n\n")
					w.(http.Flusher).Flush()
				}
			}))
			t.Cleanup(up.Close)
			px := httptest.NewServer(srv)
			t.Cleanup(px.Close)
			pu, _ := url.Parse(px.URL)
			pu.User = url.UserPassword("x", tokAlpha)
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
			resp, err := client.Get(up.URL + "/events")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			first := make([]byte, len("data: first\n\n"))
			if _, err := io.ReadFull(resp.Body, first); err != nil {
				t.Fatalf("first event: %v", err)
			}
			if how == "stopped" {
				srv.SetStoppedAgents([]string{agentAlpha})
			} else {
				srv.SetAgents(map[string]string{"beta": tokBeta})
			}
			start := time.Now()
			_, err = io.ReadAll(resp.Body)
			if err == nil {
				t.Fatal("the cut stream looked complete")
			}
			if el := time.Since(start); el > 2*time.Second {
				t.Fatalf("stream cut after %v", el)
			}
			r := lastReceiptOf(t, chainFile)
			if r.Decision != gwDeny || len(r.Reasons) != 1 || r.Reasons[0] != "agent_stopped_mid_response" {
				t.Fatalf("receipt %+v", r)
			}
		})
	}
}

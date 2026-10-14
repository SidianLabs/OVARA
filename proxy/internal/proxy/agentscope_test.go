package proxy

import (
	"net/http"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

// A scoped agent acts only on what its allow list names; a sub-agent's
// list fits inside its parent's and stopping the parent stops it; who an
// agent acts for is shown with every approval and recorded in every
// receipt.

func TestAgentScope_LimitsWhatAnAgentMayDo(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	host := mustHostPort(t, up.URL)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "child": tokBeta})
	srv.SetAgentScopes(map[string]config.AgentScope{
		agentAlpha: {Allow: []string{"GET http://" + host + "/ok/*"}, For: "alice@example.com"},
		"child":    {Parent: agentAlpha, Allow: []string{"GET http://" + host + "/ok/x"}},
	})

	if rec := send(srv, http.MethodGet, up.URL+"/ok/x", "", nil, asAgent(tokAlpha)); rec.Code != 200 {
		t.Fatalf("in scope: %d %s", rec.Code, rec.Body.String())
	}
	checks := ag.of("http.request")
	if len(checks) != 1 || checks[0].Context["for"] != "alice@example.com" || checks[0].Context["agent"] != agentAlpha {
		t.Fatalf("the gateway was not told who the agent acts for: %+v", checks)
	}
	if r := lastReceiptOf(t, chainFile); !containsString(r.Reasons, "for:alice@example.com") || r.Agent != agentAlpha {
		t.Fatalf("receipt: %+v", r)
	}

	for _, c := range []struct{ method, path string }{{http.MethodPost, "/ok/x"}, {http.MethodGet, "/other"}} {
		rec := send(srv, c.method, up.URL+c.path, "", nil, asAgent(tokAlpha))
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "outside the scope of agent "+agentAlpha) {
			t.Fatalf("%s %s out of scope: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
		if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "agent_scope") {
			t.Fatalf("receipt: %+v", r)
		}
	}
	if n := len(ag.of("http.request")); n != 1 {
		t.Fatalf("an out-of-scope request reached the gateway (%d checks)", n)
	}
	if up.hits.Load() != 1 {
		t.Fatalf("upstream hits %d, want 1", up.hits.Load())
	}

	// The sub-agent: only what its own (narrower) list names.
	if rec := send(srv, http.MethodGet, up.URL+"/ok/x", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("child in scope: %d", rec.Code)
	}
	if rec := send(srv, http.MethodGet, up.URL+"/ok/y", "", nil, asAgent(tokBeta)); rec.Code != 403 {
		t.Fatalf("child beyond its list: %d", rec.Code)
	}
	// Stopping the parent stops the sub-agent.
	srv.SetStoppedAgents([]string{agentAlpha})
	if rec := send(srv, http.MethodGet, up.URL+"/ok/x", "", nil, asAgent(tokBeta)); rec.Code != 403 || !strings.Contains(rec.Body.String(), agentStoppedMessage) {
		t.Fatalf("child of a stopped parent: %d %s", rec.Code, rec.Body.String())
	}
	srv.SetStoppedAgents(nil)
	if rec := send(srv, http.MethodGet, up.URL+"/ok/x", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("child after the parent is restored: %d", rec.Code)
	}
}

func TestAgentScope_UnscopedAgentsAreUnchanged(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "free": tokBeta})
	srv.SetAgentScopes(map[string]config.AgentScope{agentAlpha: {Allow: []string{"GET https://nowhere/*"}}})
	if rec := send(srv, http.MethodPost, up.URL+"/anything", "", nil, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("an agent without a scope: %d", rec.Code)
	}
	if rec := send(srv, http.MethodPost, up.URL+"/anything", "", nil, asAgent(tokAlpha)); rec.Code != 403 {
		t.Fatalf("the scoped one: %d", rec.Code)
	}
}

func TestAgentScope_CoversTunnels(t *testing.T) {
	srv, ag, chainFile, proxyAddr := tcpGateServer(t, "allow")
	echo, accepts := echoServer(t)
	other, _ := echoServer(t)
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha})
	srv.SetAgentScopes(map[string]config.AgentScope{agentAlpha: {Allow: []string{"tcp:" + echo}}})

	c, br, status, _ := connectThrough(t, proxyAddr, echo, asAgent(tokAlpha))
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("in-scope tunnel: %s", status)
	}
	roundTrip(t, c, br, "scoped")
	c.Close()

	c2, _, status2, body := connectThrough(t, proxyAddr, other, asAgent(tokAlpha))
	defer c2.Close()
	if !strings.HasPrefix(status2, "403") || !strings.Contains(string(body), "outside the scope") {
		t.Fatalf("out-of-scope tunnel: %s %s", status2, body)
	}
	if n := len(ag.of(actionTCPConnect)); n != 1 {
		t.Fatalf("the out-of-scope tunnel reached the gateway (%d checks)", n)
	}
	if accepts.Load() != 1 {
		t.Fatalf("destination accepts %d", accepts.Load())
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "agent_scope") {
		t.Fatalf("receipt: %+v", r)
	}
}

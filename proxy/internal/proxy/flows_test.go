package proxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
)

// Flow rules: after a read from a rule's sources, a write to a destination
// the rule does not list is asked about or refused, for the rule's window.

func TestFlows_WritesOutsideTheFlowAreAsked(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	host := mustHostPort(t, up.URL)
	srv.SetFlows([]config.Flow{{Name: "crm", Sources: []string{"http://" + host + "/crm/*"}, Destinations: []string{"http://" + host + "/crm/*", "http://" + host + "/ticketing/*"}}})
	ag.setDecision(actionFlowWrite, "deny")

	// Before any read from the source: writes anywhere are unasked.
	if rec := send(srv, http.MethodPost, up.URL+"/paste", "text/plain", strings.NewReader("x"), nil); rec.Code != 200 {
		t.Fatalf("write before the read: %d", rec.Code)
	}
	if rec := send(srv, http.MethodGet, up.URL+"/crm/customers/1", "", nil, nil); rec.Code != 200 {
		t.Fatalf("the read: %d", rec.Code)
	}
	// Now a write elsewhere is a question (refused here); to a listed
	// destination it is not.
	rec := send(srv, http.MethodPost, up.URL+"/paste", "text/plain", strings.NewReader("customer data"), nil)
	if rec.Code != 403 || up.hits.Load() != 2 {
		t.Fatalf("write outside the flow after the read: %d, hits %d", rec.Code, up.hits.Load())
	}
	c := ag.of(actionFlowWrite)
	if len(c) != 1 || c[0].Resource != "flow:crm POST http://"+host+"/paste" || !strings.Contains(c[0].Context["flow"], "read from http://"+host+"/crm/customers/1") {
		t.Fatalf("asked %+v", c)
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "flow:crm") {
		t.Fatalf("receipt: %+v", r)
	}
	if rec := send(srv, http.MethodPost, up.URL+"/ticketing/new", "text/plain", strings.NewReader("ok"), nil); rec.Code != 200 || len(ag.of(actionFlowWrite)) != 1 {
		t.Fatalf("write to a listed destination: %d", rec.Code)
	}
	// Reads are never asked about.
	if rec := send(srv, http.MethodGet, up.URL+"/anything", "", nil, nil); rec.Code != 200 || len(ag.of(actionFlowWrite)) != 1 {
		t.Fatalf("a read under a flow: %d", rec.Code)
	}
	// Past the window the mark is gone.
	srv.flows.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if rec := send(srv, http.MethodPost, up.URL+"/paste", "text/plain", strings.NewReader("later"), nil); rec.Code != 200 {
		t.Fatalf("write after the window: %d", rec.Code)
	}
}

func TestFlows_DenyEffectRefusesWithoutAsking(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	host := mustHostPort(t, up.URL)
	srv.SetFlows([]config.Flow{{Name: "secrets", Sources: []string{"http://" + host + "/vault/*"}, Effect: "deny", WindowMinutes: 5}})
	if rec := send(srv, http.MethodGet, up.URL+"/vault/key", "", nil, nil); rec.Code != 200 {
		t.Fatalf("the read: %d", rec.Code)
	}
	rec := send(srv, http.MethodPost, up.URL+"/anywhere", "text/plain", strings.NewReader("leak"), nil)
	if rec.Code != 403 || up.hits.Load() != 1 || len(ag.of(actionFlowWrite)) != 0 {
		t.Fatalf("deny flow: %d, hits %d, asked %d", rec.Code, up.hits.Load(), len(ag.of(actionFlowWrite)))
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "flow:secrets") {
		t.Fatalf("receipt: %+v", r)
	}
	// Marks are per agent: another agent is free.
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha, "beta": tokBeta})
	if rec := send(srv, http.MethodPost, up.URL+"/anywhere", "text/plain", strings.NewReader("mine"), asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("another agent: %d", rec.Code)
	}
}

func TestValidateFlowsAndDLP(t *testing.T) {
	good := []config.Flow{{Name: "a", Sources: []string{"https://x/*"}}, {Name: "b", Sources: []string{"https://y/*"}, Effect: "deny", WindowMinutes: 10}}
	if err := config.ValidateFlows(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]config.Flow{
		"no name":    {{Sources: []string{"https://x/*"}}},
		"no sources": {{Name: "a"}},
		"dup":        {{Name: "a", Sources: []string{"x"}}, {Name: "a", Sources: []string{"y"}}},
		"effect":     {{Name: "a", Sources: []string{"x"}, Effect: "maybe"}},
	} {
		if err := config.ValidateFlows(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (&config.DLP{Patterns: []config.DLPPattern{{Name: "ok_1", Regex: `X-[0-9]+`}}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]config.DLP{
		"bad name":  {Patterns: []config.DLPPattern{{Name: "Bad Name", Regex: "x"}}},
		"bad regex": {Patterns: []config.DLPPattern{{Name: "x", Regex: "("}}},
		"empty":     {Patterns: []config.DLPPattern{{Name: "x"}}},
	} {
		b := bad
		if err := b.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

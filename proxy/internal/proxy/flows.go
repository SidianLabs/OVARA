package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ovara.proxy/internal/config"
)

// Flow rules: the confidentiality side of the taint rule. The taint rule
// says "what the agent just read may be lying to it"; a flow rule says
// "what the agent just read must not go elsewhere". For a while after a
// read from one of a rule's sources, every write that policy would let
// through on its own to a destination the rule does not list is asked
// about (flow.write on "flow:<name> <METHOD> <url>"), with the source and
// its age in front of the person, or refused when the rule says deny.
// State is kept per agent name and lasts one run.

const (
	actionFlowWrite   = "flow.write"
	defaultFlowWindow = 30 * time.Minute
)

type flowRule struct {
	name         string
	sources      []string
	destinations []string
	window       time.Duration
	deny         bool
}

type flowMark struct {
	at     time.Time
	source string
}

type flowTracker struct {
	mu    sync.Mutex
	rules []flowRule
	marks map[string]map[string]flowMark // agent -> flow name -> latest read
	now   func() time.Time
}

// SetFlows installs the flow rules (config.ValidateFlows is the caller's);
// none turns the rules off.
func (s *Server) SetFlows(flows []config.Flow) {
	if len(flows) == 0 {
		s.flows = nil
		return
	}
	t := &flowTracker{marks: map[string]map[string]flowMark{}, now: time.Now}
	for _, f := range flows {
		w := time.Duration(f.WindowMinutes) * time.Minute
		if w <= 0 {
			w = defaultFlowWindow
		}
		t.rules = append(t.rules, flowRule{name: f.Name, sources: f.Sources, destinations: f.Destinations, window: w, deny: f.Effect == gwDeny})
	}
	s.flows = t
}

// flowsOfRead names the flows a read starts, "" when none.
func (s *Server) flowsOfRead(r *http.Request) []string {
	t := s.flows
	if t == nil || !isReadMethod(r.Method) {
		return nil
	}
	u := matchURL(r)
	var names []string
	for _, f := range t.rules {
		if matchAny(f.sources, u) {
			names = append(names, f.name)
		}
	}
	return names
}

// noteFlowRead marks the agent for each flow once the read has gone out.
func (s *Server) noteFlowRead(ctx context.Context, flows []string, source string) {
	t := s.flows
	if t == nil || len(flows) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	agent := agentKey(ctx)
	m := t.marks[agent]
	if m == nil {
		m = map[string]flowMark{}
		t.marks[agent] = m
	}
	for _, f := range flows {
		m[f] = flowMark{at: t.now(), source: source}
	}
}

// violated returns the first rule the agent is marked under whose
// destinations do not cover u, with the mark and its age.
func (t *flowTracker) violated(agent, u string) (flowRule, flowMark, time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	marks := t.marks[agent]
	for _, f := range t.rules {
		m, ok := marks[f.name]
		if !ok {
			continue
		}
		age := t.now().Sub(m.at)
		if age >= f.window {
			delete(marks, f.name)
			continue
		}
		if matchAny(f.destinations, u) {
			continue
		}
		return f, m, age, true
	}
	return flowRule{}, flowMark{}, 0, false
}

// checkFlows asks about (or refuses) a write policy allowed that a flow
// rule the agent is marked under does not cover. It returns pkgAllow when
// no rule applies, else the outcome and approval id of the question (or
// pkgDeny for a deny rule), and the reason for the receipt.
func (s *Server) checkFlows(r *http.Request, hb *heldBody, url string) (string, string, string) {
	t := s.flows
	if t == nil || isReadMethod(r.Method) || r.Method == http.MethodOptions || isUploadPackPost(r) {
		return pkgAllow, "", ""
	}
	u := matchURL(r)
	f, m, age, ok := t.violated(agentKey(r.Context()), u)
	if !ok {
		return pkgAllow, "", ""
	}
	reason := "flow:" + f.name
	if f.deny {
		return pkgDeny, "", reason
	}
	preview := requestContext(r, hb)
	if preview == nil {
		preview = map[string]string{}
	}
	preview["flow"] = fmt.Sprintf("under flow rule %q the agent read from %s %s ago; %s is not among the rule's destinations (%s)", f.name, m.source, age.Round(time.Second), u, strings.Join(f.destinations, ", "))
	preview["why"] = "what was read from the rule's sources may only go to its destinations; anywhere else a person decides"
	outcome, id := s.askAction(r.Context(), actionFlowWrite, "flow:"+f.name+" "+r.Method+" "+url, preview, "leaves a flow")
	return outcome, id, reason
}

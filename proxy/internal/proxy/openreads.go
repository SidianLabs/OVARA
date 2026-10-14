package proxy

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// A profile that lets reads through to any host ("[open read]" in the
// rule's description: the balanced and observe profiles) leaves one data
// channel the per-request and per-host limits do not close: the host name
// itself, a new one per request. The open-read budget counts, per agent,
// the distinct hosts read under such a rule. Past the cap a person is
// asked once per further host (action_type "egress.open_hosts", resource
// "host:<host>"); an approval admits that host for the rest of the run.
// Hosts a rule names (the trusted list, a preset, a host trusted for this
// run) match their own rule and are never counted.

const (
	actionOpenHosts  = "egress.open_hosts"
	openReadMarker   = "[open read]"
	defaultOpenHosts = 50
)

type openReads struct {
	mu      sync.Mutex
	max     int
	hosts   map[string]map[string]bool // agent -> hosts admitted this run
	pending map[string]*pkgResult      // agent + " " + host -> the question in flight
}

func newOpenReads(max int) *openReads {
	if max <= 0 {
		max = defaultOpenHosts
	}
	return &openReads{max: max, hosts: map[string]map[string]bool{}, pending: map[string]*pkgResult{}}
}

// SetOpenReads turns the per-agent cap on or off (default on) and sets it;
// zero keeps the default.
func (s *Server) SetOpenReads(on bool, maxHosts int) {
	if !on {
		s.openReads = nil
		return
	}
	s.openReads = newOpenReads(maxHosts)
}

// isOpenRead reports a read the policy allowed under a rule that allows
// reads from any host.
func isOpenRead(matchedRule, decision, method string) bool {
	if decision != gwAllow || (method != http.MethodGet && method != http.MethodHead) {
		return false
	}
	return strings.Contains(matchedRule, openReadMarker)
}

// checkOpenHosts admits host for the agent behind ctx, asking a person
// when the agent has already read from as many unlisted hosts as the cap
// allows. Parallel requests for one host share one question. It returns
// pkgAllow or the outcome of the question, and the approval id.
func (s *Server) checkOpenHosts(ctx context.Context, host string) (string, string) {
	b := s.openReads
	if b == nil {
		return pkgAllow, ""
	}
	agent := agentOf(ctx).name
	b.mu.Lock()
	set := b.hosts[agent]
	if set == nil {
		set = map[string]bool{}
		b.hosts[agent] = set
	}
	if set[host] || len(set) < b.max {
		set[host] = true
		b.mu.Unlock()
		return pkgAllow, ""
	}
	key := agent + " " + host
	if p := b.pending[key]; p != nil {
		b.mu.Unlock()
		select {
		case <-p.done:
		case <-ctx.Done():
			return pkgAborted, ""
		}
		if p.outcome == pkgAllow || p.outcome == pkgApproved {
			return pkgAllow, p.approvalID
		}
		return p.outcome, p.approvalID
	}
	p := &pkgResult{done: make(chan struct{})}
	b.pending[key] = p
	preview := map[string]string{
		"host":           host,
		"hosts_this_run": strconv.Itoa(len(set)),
		"cap":            strconv.Itoa(b.max),
		"why":            "the agent has read from as many unlisted hosts as the open-read cap allows this run, and each new host name can carry data out; approving admits this host for the rest of the run (a rule in policy.json names it for good)",
	}
	b.mu.Unlock()

	p.outcome, p.approvalID = s.askAction(ctx, actionOpenHosts, "host:"+host, preview, "is one more unlisted host past the open-read cap")
	b.mu.Lock()
	if p.outcome == pkgAllow || p.outcome == pkgApproved {
		b.hosts[agent][host] = true
	}
	delete(b.pending, key)
	b.mu.Unlock()
	close(p.done)
	if p.outcome == pkgAllow || p.outcome == pkgApproved {
		return pkgAllow, p.approvalID
	}
	return p.outcome, p.approvalID
}

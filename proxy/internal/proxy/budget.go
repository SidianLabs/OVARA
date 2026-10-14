package proxy

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Every allowed request is small, but nothing bounded how many there were:
// an agent could move any amount of data to a host policy trusts, a few
// hundred bytes at a time. The egress budget counts allowed requests and
// request bytes per destination host per minute. Past it, a person is asked
// (action_type "egress.budget", resource "budget:<host>"); an approval
// doubles that host's allowance for the rest of the run, so a busy but
// legitimate job pauses once, not every minute.

const (
	actionEgressBudget = "egress.budget"

	defaultBudgetRequests = 600     // per host per minute
	defaultBudgetBytes    = 8 << 20 // request bytes per host per minute
	budgetWindow          = time.Minute
)

// Package registries see thousands of small requests during one clean
// install (metadata plus every tarball), all of them reads of names the
// install already chose. They start with a larger allowance so an ordinary
// install does not pause; data hidden in fake package names still meets the
// same limit, just later.
const registryBudgetMult = 10

var packageRegistryHosts = map[string]bool{
	"registry.npmjs.org": true, "registry.yarnpkg.com": true,
	"pypi.org": true, "files.pythonhosted.org": true,
	"proxy.golang.org": true, "sum.golang.org": true,
	"index.crates.io": true, "static.crates.io": true,
	"rubygems.org": true, "repo.maven.apache.org": true, "repo1.maven.org": true,
}

type hostBudget struct {
	start   time.Time
	reqs    int
	bytes   int64
	mult    int64      // allowance multiplier; doubles on each approval
	pending *pkgResult // the question in flight for this host, if any
}

type egressBudget struct {
	mu       sync.Mutex
	reqLimit int
	byteLim  int64
	hosts    map[string]*hostBudget
	now      func() time.Time
}

func newEgressBudget(reqs int, bytes int64) *egressBudget {
	if reqs <= 0 {
		reqs = defaultBudgetRequests
	}
	if bytes <= 0 {
		bytes = defaultBudgetBytes
	}
	return &egressBudget{reqLimit: reqs, byteLim: bytes, hosts: map[string]*hostBudget{}, now: time.Now}
}

// SetEgressBudget turns the per-host budget on or off (default on) and sets
// its allowance; zero keeps a default.
func (s *Server) SetEgressBudget(on bool, requestsPerMinute int, bytesPerMinute int64) {
	if !on {
		s.budget = nil
		return
	}
	s.budget = newEgressBudget(requestsPerMinute, bytesPerMinute)
}

// host returns host's counters, starting a new window when the last one ended.
// Called with mu held.
func (b *egressBudget) host(host string) *hostBudget {
	h := b.hosts[host]
	if h == nil {
		h = &hostBudget{mult: 1}
		if packageRegistryHosts[host] {
			h.mult = registryBudgetMult
		}
		b.hosts[host] = h
	}
	if now := b.now(); now.Sub(h.start) >= budgetWindow {
		h.start, h.reqs, h.bytes = now, 0, 0
	}
	return h
}

// take charges one request of n bytes to host if it fits the allowance.
func (b *egressBudget) take(host string, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.host(host)
	if h.reqs+1 > b.reqLimit*int(h.mult) || h.bytes+n > b.byteLim*h.mult {
		return false
	}
	h.reqs++
	h.bytes += n
	return true
}

// checkBudget charges one allowed request to host, asking a person when it
// does not fit. Parallel requests over the budget share one question. It
// returns pkgAllow or the outcome of the question, and the approval id.
func (s *Server) checkBudget(ctx context.Context, host string, n int64) (string, string) {
	b := s.budget
	if b == nil || b.take(host, n) {
		return pkgAllow, ""
	}
	b.mu.Lock()
	h := b.host(host)
	if p := h.pending; p != nil {
		b.mu.Unlock()
		select {
		case <-p.done:
		case <-ctx.Done():
			return pkgAborted, ""
		}
		if p.outcome == pkgAllow || p.outcome == pkgApproved {
			b.charge(host, n)
			return pkgAllow, p.approvalID
		}
		return p.outcome, p.approvalID
	}
	p := &pkgResult{done: make(chan struct{})}
	h.pending = p
	preview := map[string]string{
		"host":          host,
		"this_minute":   fmt.Sprintf("%d requests, %d bytes so far", h.reqs, h.bytes),
		"allowance":     fmt.Sprintf("%d requests and %d bytes per minute", b.reqLimit*int(h.mult), b.byteLim*h.mult),
		"why":           "an agent sending many small allowed requests can move data out a little at a time; approving doubles this host's allowance for the rest of the run",
		"request_bytes": strconv.FormatInt(n, 10),
	}
	b.mu.Unlock()

	p.outcome, p.approvalID = s.askAction(ctx, actionEgressBudget, "budget:"+host, preview, "is over its egress budget")
	b.mu.Lock()
	if p.outcome == pkgAllow || p.outcome == pkgApproved {
		h.mult *= 2
	}
	h.pending = nil
	b.mu.Unlock()
	close(p.done)
	if p.outcome == pkgAllow || p.outcome == pkgApproved {
		b.charge(host, n)
		return pkgAllow, p.approvalID
	}
	return p.outcome, p.approvalID
}

// charge counts a request a person let through over the budget.
func (b *egressBudget) charge(host string, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.host(host)
	h.reqs++
	h.bytes += n
}

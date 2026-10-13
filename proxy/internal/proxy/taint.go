package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ovara.proxy/internal/gateway"
)

// The taint rule: a small information-flow control. An agent that has just
// read content anyone can write (an issue, a pull request comment, a page
// from a host nobody vetted) may be acting on instructions hidden in it.
// For a while after such a read, every write that policy would let through
// on its own is asked about instead (action_type "taint.write", resource
// "taint:<METHOD> <url>"), with the source of the untrusted content and how
// long ago it was read in front of the person. Writes policy already asks
// about, or refuses, are unchanged. The model API itself is not a write in
// this sense: the agent has to keep talking to its model.
//
// What counts as an untrusted read:
//   - a read a person approved (a host not on the trusted list, or a
//     read the policy pauses),
//   - a read allowed by a rule added from "trust this host for reads",
//   - a read on a trusted host whose URL matches an untrusted-content
//     pattern (issues, pull request comments, discussions),
//   - a model request whose provider-side fetch a person let through.
//
// State is kept per agent name and lasts one run.

const (
	actionTaintWrite = "taint.write"

	defaultTaintWindow = 30 * time.Minute

	// runTrustRulePrefix starts the description of every rule `ovara`
	// adds from "trust this host for reads" (cmd/ovara trust_host.go); the
	// gateway names the deciding rule by its description.
	runTrustRulePrefix = "[this run only]"
)

// defaultUntrustedReads are reads on trusted hosts that return content
// third parties write: issues, pull and merge requests (their bodies,
// lists, diffs, comments and reviews), discussions and commit comments, by
// API (also by numeric repository id, the form GitHub's own pagination
// links use) and on the web. "*" matches any run of characters, "/"
// included.
var defaultUntrustedReads = []string{
	"https://api.github.com/repos/*/issues*",
	"https://api.github.com/repos/*/pulls*",
	"https://api.github.com/repos/*/discussions*",
	"https://api.github.com/repos/*/comments*",
	"https://api.github.com/repos/*/commits/*/comments*",
	"https://api.github.com/repositories/*/issues*",
	"https://api.github.com/repositories/*/pulls*",
	"https://api.github.com/repositories/*/discussions*",
	"https://api.github.com/repositories/*/comments*",
	"https://api.github.com/repositories/*/commits/*/comments*",
	"https://api.github.com/search/issues*",
	"https://api.github.com/issues*",
	"https://github.com/*/issues*",
	"https://github.com/*/pull/*",
	"https://github.com/*/pulls*",
	"https://github.com/*/commit/*",
	"https://github.com/*/discussions*",
	"https://gitlab.com/api/v4/projects/*/issues*",
	"https://gitlab.com/api/v4/projects/*/merge_requests*",
	"https://gitlab.com/api/v4/projects/*/repository/commits/*/comments*",
	"https://gitlab.com/api/v4/projects/*/repository/commits/*/discussions*",
	"https://gitlab.com/api/v4/issues*",
	"https://gitlab.com/api/v4/merge_requests*",
	"https://gitlab.com/*/-/issues*",
	"https://gitlab.com/*/-/merge_requests*",
	"https://gitlab.com/*/-/commit/*",
}

// defaultExemptWrites are writes that only read in substance: npm audit
// sends the names of the packages being installed and gets advisories back.
var defaultExemptWrites = []string{
	"https://registry.npmjs.org/-/npm/v1/security/*",
}

type taintMark struct {
	at     time.Time
	source string
}

type taintTracker struct {
	mu        sync.Mutex
	window    time.Duration
	untrusted []string
	exempt    []string
	marks     map[string]taintMark // agent name -> latest untrusted read
	now       func() time.Time
}

func newTaintTracker() *taintTracker {
	return &taintTracker{
		window: defaultTaintWindow, untrusted: defaultUntrustedReads, exempt: defaultExemptWrites,
		marks: map[string]taintMark{}, now: time.Now,
	}
}

// SetTaint turns the taint rule on or off (default on). window <= 0 keeps
// the default (30 minutes); nil pattern lists keep the defaults.
func (s *Server) SetTaint(on bool, window time.Duration, untrustedReads, exemptWrites []string) {
	if !on {
		s.taint = nil
		return
	}
	t := newTaintTracker()
	if window > 0 {
		t.window = window
	}
	if untrustedReads != nil {
		t.untrusted = untrustedReads
	}
	if exemptWrites != nil {
		t.exempt = exemptWrites
	}
	s.taint = t
}

// mark records that agent read untrusted content from source now.
func (t *taintTracker) mark(agent, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.marks[agent] = taintMark{at: t.now(), source: source}
}

// active returns the agent's latest untrusted read and its age, if it is
// inside the window.
func (t *taintTracker) active(agent string) (taintMark, time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.marks[agent]
	if !ok {
		return taintMark{}, 0, false
	}
	age := t.now().Sub(m.at)
	if age >= t.window {
		delete(t.marks, agent)
		return taintMark{}, 0, false
	}
	return m, age, true
}

// globMatch reports whether s matches pattern, where "*" matches any run of
// characters (including none and "/") and everything else matches itself.
func globMatch(pattern, s string) bool {
	p, x := 0, 0
	star, mark := -1, 0
	for x < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, x
			p++
		case p < len(pattern) && pattern[p] == s[x]:
			p++
			x++
		case star >= 0:
			p = star + 1
			mark++
			x = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matchURL is the form patterns are matched against: lower case, no
// default port, no query or fragment, the path percent-decoded and runs of
// "/" collapsed, so a respelt path still matches.
func matchURL(r *http.Request) string {
	scheme := strings.ToLower(r.URL.Scheme)
	host := normalizeHost(r.URL.Hostname())
	if p := r.URL.Port(); p != "" && !(scheme == "https" && p == "443") && !(scheme == "http" && p == "80") {
		host += ":" + p
	}
	p := r.URL.Path
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return strings.ToLower(scheme + "://" + host + p)
}

func matchAny(patterns []string, u string) bool {
	for _, p := range patterns {
		if globMatch(strings.ToLower(p), u) {
			return true
		}
	}
	return false
}

func isReadMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// readTaintSource returns what makes this request an untrusted read, or "".
// d is the URL decision (an "escalate" here was approved: the request is
// about to go out); modelFinding is a model-gate finding a person or the
// policy let through.
func (s *Server) readTaintSource(r *http.Request, d *gateway.Decision, modelFinding string) string {
	t := s.taint
	if t == nil || d == nil {
		return ""
	}
	if modelFinding != "" {
		return "a model request that made the provider fetch remote content (" + modelFinding + ")"
	}
	if !isReadMethod(r.Method) {
		return ""
	}
	u := matchURL(r)
	switch {
	case d.Decision == "escalate":
		return "a read a person approved (" + u + ")"
	case strings.HasPrefix(d.MatchedRule, runTrustRulePrefix):
		return "a host trusted for reads from an approval prompt (" + u + ")"
	case matchAny(t.untrusted, u):
		return u
	}
	return ""
}

// noteRead marks the agent once an untrusted read has gone out.
func (s *Server) noteRead(ctx context.Context, source string) {
	if s.taint != nil && source != "" {
		s.taint.mark(agentKey(ctx), source)
	}
}

// taintedWrite returns the agent's untrusted read that makes this request
// a question, and its age; ok is false when the request is not a write
// the rule covers or the agent is not tainted.
func (s *Server) taintedWrite(r *http.Request, host string) (taintMark, time.Duration, bool) {
	t := s.taint
	if t == nil || isReadMethod(r.Method) || r.Method == http.MethodOptions {
		return taintMark{}, 0, false
	}
	// The model API is how the agent works at all; git fetches are reads.
	if s.isModelHost(host) || isUploadPackPost(r) || matchAny(t.exempt, matchURL(r)) {
		return taintMark{}, 0, false
	}
	return t.active(agentKey(r.Context()))
}

// checkTaint asks about a write policy allowed while the agent is tainted.
// It returns pkgAllow when the rule does not apply, else the outcome of the
// question and its approval id, and the reason to record in the receipt.
func (s *Server) checkTaint(r *http.Request, hb *heldBody, url, host string) (string, string, string) {
	m, age, ok := s.taintedWrite(r, host)
	if !ok {
		return pkgAllow, "", ""
	}
	preview := requestContext(r, hb)
	if preview == nil {
		preview = map[string]string{}
	}
	preview["taint"] = fmt.Sprintf("the agent read untrusted content from %s %s ago", m.source, age.Round(time.Second))
	preview["why"] = "content anyone can write may carry instructions for the agent; writes it makes soon after reading such content are checked by a person"
	outcome, id := s.askAction(r.Context(), actionTaintWrite, "taint:"+r.Method+" "+url, preview, "follows an untrusted read")
	return outcome, id, "tainted_by:" + m.source
}

// agentQuestions asks the per-agent questions about a request policy
// allowed: a write while the agent is tainted, then a model call past the
// agent's budget. second answers each (handleRequest's closure); it returns
// false when the request must stop.
func (s *Server) agentQuestions(r *http.Request, hb *heldBody, url string, facts *receiptFacts, second func(string, string, map[string]any) bool) bool {
	host := normalizeHost(r.URL.Hostname())
	outcome, id, reason := s.checkTaint(r, hb, url, host)
	if reason != "" {
		facts.reasons = append(facts.reasons, reason)
	}
	if !second(outcome, id, map[string]any{"error": "action denied", "reasons": []string{"tainted_write"}}) {
		return false
	}
	outcome, id = s.checkModelBudget(r.Context(), r, host)
	return second(outcome, id, map[string]any{"error": "model budget exceeded", "reasons": []string{"model_budget_exceeded"}, "host": host})
}

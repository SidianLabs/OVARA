// Package policy compiles rules into an IR and evaluates with total,
// deterministic semantics (spec/policy_ir.md). Two evaluators exist:
// Eval (the real one) and ReferenceEval (naive, ~50 lines, the
// differential oracle for P11).
package policy

import (
	"fmt"
	"sort"
	"strings"

	"ovara.dev/v2/action"
)

type Effect string

const (
	Allow       Effect = "allow"
	Deny        Effect = "deny"
	Escalate    Effect = "escalate"
	RequireCap  Effect = "require_capability"
)

type Selector struct {
	Types     []string `json:"types"`     // closed enum or "*"
	Resources []string `json:"resources"` // canonical patterns, * suffix prefix-match
	Envs      []string `json:"envs"`      // env set or "*"
	Actors    []string `json:"actors"`    // principal ids or "*"
}

type Rule struct {
	ID       string   `json:"id"`
	Sel      Selector `json:"selector"`
	Effect   Effect   `json:"effect"`
	Span     string   `json:"span"` // provenance: POLICY.md offset / file:line
	Priority int      `json:"priority"`
}

type Policy struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
	Default Effect `json:"default"` // deny | escalate
}

// Decision is the evaluator output. ReasonClass is the agent-visible
// coarse class; Trace is operator-visible detail (spec §5 split).
type Decision struct {
	Outcome     Effect   `json:"outcome"`
	ReasonClass string   `json:"reason_class"`
	MatchedIDs  []string `json:"matched_ids,omitempty"` // op-visible
	PolicyID    string   `json:"policy_id"`
}

// Eval applies the total-order semantics (spec §2):
// any deny → deny; else any escalate → escalate; else any require →
// require; else any allow → allow; else default.
func Eval(p *Policy, a action.Action, actor string) Decision {
	var deny, esc, req, allow []string
	for _, r := range p.Rules {
		if !match(r.Sel, a, actor) {
			continue
		}
		switch r.Effect {
		case Deny:
			deny = append(deny, r.ID)
		case Escalate:
			esc = append(esc, r.ID)
		case RequireCap:
			req = append(req, r.ID)
		case Allow:
			allow = append(allow, r.ID)
		}
	}
	d := Decision{PolicyID: p.ID()}
	switch {
	case len(deny) > 0:
		d.Outcome, d.ReasonClass, d.MatchedIDs = Deny, "policy_denied", deny
	case len(esc) > 0:
		d.Outcome, d.ReasonClass, d.MatchedIDs = Escalate, "requires_approval", esc
	case len(req) > 0:
		d.Outcome, d.ReasonClass, d.MatchedIDs = RequireCap, "capability_missing", req
	case len(allow) > 0:
		d.Outcome, d.ReasonClass, d.MatchedIDs = Allow, "policy_allowed", allow
	default:
		d.Outcome = p.Default
		d.ReasonClass = map[Effect]string{
			Deny: "policy_denied", Escalate: "requires_approval",
			Allow: "policy_allowed", RequireCap: "capability_missing",
		}[p.Default]
	}
	return d
}

// ReferenceEval is the intentionally naive oracle — O(n) scan, same
// semantics spelled out again. Eval and ReferenceEval must agree on
// every input (differential test target).
func ReferenceEval(p *Policy, a action.Action, actor string) Effect {
	var hasDeny, hasEsc, hasReq, hasAllow bool
	for _, r := range p.Rules {
		if match(r.Sel, a, actor) {
			switch r.Effect {
			case Deny:
				hasDeny = true
			case Escalate:
				hasEsc = true
			case RequireCap:
				hasReq = true
			case Allow:
				hasAllow = true
			}
		}
	}
	switch {
	case hasDeny:
		return Deny
	case hasEsc:
		return Escalate
	case hasReq:
		return RequireCap
	case hasAllow:
		return Allow
	}
	return p.Default
}

func match(sel Selector, a action.Action, actor string) bool {
	return matchSet(sel.Types, string(a.Type)) &&
		matchPatterns(sel.Resources, a.Resource) &&
		matchSet(sel.Envs, string(a.Env)) &&
		matchSet(sel.Actors, actor)
}

func matchSet(set []string, v string) bool {
	if len(set) == 0 {
		return true // empty selector dim = wildcard
	}
	for _, s := range set {
		if s == "*" || s == v {
			return true
		}
	}
	return false
}

func matchPatterns(pats []string, res string) bool {
	if len(pats) == 0 {
		return true
	}
	for _, p := range pats {
		if p == "*" || p == res {
			return true
		}
		if strings.HasSuffix(p, "*") && strings.HasPrefix(res, strings.TrimSuffix(p, "*")) {
			return true
		}
		// host-label-boundary suffix match on the HOST portion only:
		// "https://*.github.com" matches "https://api.github.com/x" but
		// NOT "https://api.github.com.evil.com/x" (SEC-0010 class —
		// boundary chars prevent suffix-append attacks)
		phost := p
		if i := strings.Index(p, "://"); i >= 0 {
			phost = p[i+3:]
		}
		rhost := res
		if i := strings.Index(res, "://"); i >= 0 {
			rhost = res[i+3:]
		}
		if j := strings.IndexAny(rhost, "/:"); j >= 0 {
			rhost = rhost[:j]
		}
		if strings.HasPrefix(phost, "*.") {
			suffix := phost[1:] // ".github.com"
			if strings.HasSuffix(rhost, suffix) && len(rhost) > len(suffix) {
				return true
			}
		}
	}
	return false
}

// ID is a content hash over the policy — decisions cite it for
// reproducibility (P11: same input+state ⇒ same decision).
func (p *Policy) ID() string {
	var b strings.Builder
	b.WriteString(p.Version)
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "|%s:%s", r.ID, r.Effect)
	}
	return fmt.Sprintf("pol_%x", fnv(b.String()))
}

func fnv(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Diagnostics runs shadow/conflict analysis at compile time (spec §4).
func Diagnostics(p *Policy) []string {
	var out []string
	// contradiction: same selector set, different effects
	for i, r1 := range p.Rules {
		for j := i + 1; j < len(p.Rules); j++ {
			r2 := p.Rules[j]
			if selEqual(r1.Sel, r2.Sel) && r1.Effect != r2.Effect {
				out = append(out, fmt.Sprintf(
					"contradiction: rules %s and %s same selector, effects %s vs %s (deny wins at eval)",
					r1.ID, r2.ID, r1.Effect, r2.Effect))
			}
		}
	}
	// shadowed: a deny/escalate whose selector ⊇ a lower-precedence
	// allow → the allow is unreachable for those inputs. Approximate:
	// same non-resource selectors and resource-superset.
	for _, allowR := range p.Rules {
		if allowR.Effect != Allow {
			continue
		}
		for _, other := range p.Rules {
			if other.Effect == Allow || other.ID == allowR.ID {
				continue
			}
			if coversSelector(other.Sel, allowR.Sel) {
				out = append(out, fmt.Sprintf(
					"shadowed: allow rule %s unreachable under %s rule %s",
					allowR.ID, other.Effect, other.ID))
			}
		}
	}
	sort.Strings(out)
	return out
}

func selEqual(a, b Selector) bool {
	return same(a.Types, b.Types) && same(a.Resources, b.Resources) &&
		same(a.Envs, b.Envs) && same(a.Actors, b.Actors)
}

func same(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	sx, sy := append([]string{}, x...), append([]string{}, y...)
	sort.Strings(sx)
	sort.Strings(sy)
	for i := range sx {
		if sx[i] != sy[i] {
			return false
		}
	}
	return true
}

// coversSelector: does outer's selector match everything inner's does?
// Approximation: outer is "*" or equal in every dimension.
func coversSelector(outer, inner Selector) bool {
	dims := [][2][]string{
		{outer.Types, inner.Types}, {outer.Resources, inner.Resources},
		{outer.Envs, inner.Envs}, {outer.Actors, inner.Actors},
	}
	for _, d := range dims {
		o, i := d[0], d[1]
		if matchSet(o, "*") {
			continue
		}
		ok := true
		for _, v := range i {
			if !matchSet(o, v) && !(strings.HasSuffix(v, "*") && len(v) > 1) {
				// inner has a value outer doesn't cover
				ok = matchSet(o, strings.TrimSuffix(v, "*"))
				if !ok {
					break
				}
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

package identity

// Restricted delegation scope grammar — P1.1 F-3.
//
// A scope is either:
//   - "*"            unbounded (matches every resource; only valid as the
//                    root of a delegation chain, e.g. scope-less hops)
//   - [METHOD " "] <url> ["*"]   URL scope; a single trailing "*" means
//                    path-prefix, no "*" means exact
//   - <literal> ["*"]            non-URL literal scope (no space, no "://")
//
// URL forms are canonicalized through policy.CanonicalResource (method
// split, scheme/host lowercase, default-port drop, dot-segment cleanup,
// userinfo rejection). Anything else — mid-string stars, "x y" literals,
// fragments/queries inside scopes, traversal that survives cleaning —
// fails closed at parse time or containment time.
//
// Invariant: scopeContains(P,C) ⇒ every resource matched by C is also
// matched by P. Enforced by comparing canonical literal prefixes inside
// a single domain (URL vs literal); the property test exercises it.

import (
	"errors"
	"net/url"
	"strings"

	"ovara.runtime.gateway/internal/policy"
)

type scopePat struct {
	isURL  bool   // URL domain vs literal domain
	method string // URL only: "" = method-agnostic
	lit    string // canonical literal (URL part for URL scopes)
	wild   bool   // trailing-* prefix
}

var errScope = errors.New("invalid delegation scope")

// canonResourceURL returns (method, canonicalURL) for a resource or
// scope literal. Method-prefixed input canonicalizes via
// policy.CanonicalResource; bare URLs get a borrowed GET so the same
// canonical form applies (method "" reported for those).
func canonResourceURL(s string) (method, canon string, ok bool) {
	c, ok := policy.CanonicalResource(s)
	if !ok {
		if strings.ContainsAny(s, " \t") {
			return "", "", false
		}
		c, ok = policy.CanonicalResource("GET " + s)
		if !ok {
			return "", "", false
		}
		return "", c[len("GET "):], true
	}
	i := strings.IndexByte(c, ' ')
	return c[:i], c[i+1:], true
}

func parseScope(s string) (scopePat, error) {
	var p scopePat
	if s == "*" {
		p.wild = true // lit "" = unbounded
		return p, nil
	}
	lit, wild := s, false
	if strings.HasSuffix(s, "*") {
		lit, wild = s[:len(s)-1], true
	}
	if lit == "" || strings.Contains(lit, "*") {
		return p, errScope
	}
	if !strings.Contains(lit, "://") {
		if strings.ContainsAny(lit, " \t") {
			return p, errScope
		}
		p.lit, p.wild = lit, wild
		return p, nil
	}
	// Strict input hygiene on the RAW form before canonicalization:
	// no query, no fragment, no dot segments — canonicalization handles
	// them harmlessly for resources, but scopes must be written plainly.
	us := lit
	if i := strings.IndexByte(lit, ' '); i > 0 {
		us = lit[i+1:]
	}
	u, err := url.Parse(us)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return p, errScope
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return p, errScope
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return p, errScope // percent-encoded dot segments
		}
	}
	m, c, ok := canonResourceURL(lit)
	if !ok {
		return p, errScope
	}
	p.isURL, p.method, p.lit, p.wild = true, m, c, wild
	return p, nil
}

func validScope(s string) bool {
	_, err := parseScope(s)
	return err == nil
}

func unbounded(p scopePat) bool { return p.wild && p.lit == "" }

// scopeMatches: does scope cover resource?
func scopeMatches(scope, resource string) bool {
	p, err := parseScope(scope)
	if err != nil {
		return false
	}
	if unbounded(p) {
		return true
	}
	if p.isURL {
		rm, rc, ok := canonResourceURL(resource)
		if !ok {
			return false
		}
		if p.method != "" && p.method != rm {
			return false
		}
		if p.wild {
			return strings.HasPrefix(rc, p.lit)
		}
		return rc == p.lit
	}
	if p.wild {
		return strings.HasPrefix(resource, p.lit)
	}
	return resource == p.lit
}

// scopeContains: is child ⊆ parent (every child-matched resource also
// parent-matched)? Same-domain only; prefix containment on canonical
// literals. Rejects rather than assumes when domains or methods differ.
func scopeContains(parent, child string) bool {
	pp, err := parseScope(parent)
	if err != nil {
		return false
	}
	if unbounded(pp) {
		return true
	}
	cp, err := parseScope(child)
	if err != nil || pp.isURL != cp.isURL {
		return false
	}
	if unbounded(cp) {
		return false // bounded parent can't contain unbounded child
	}
	if pp.isURL && pp.method != "" && pp.method != cp.method {
		return false
	}
	if pp.wild {
		return strings.HasPrefix(cp.lit, pp.lit)
	}
	return cp.lit == pp.lit && !cp.wild
}

// ScopeMatches reports whether scope covers resource (exported for the
// evaluator's terminal-capability check).
func ScopeMatches(scope, resource string) bool { return scopeMatches(scope, resource) }

// ActionInScope reports whether action is inside the capability action
// set: "*" grants any action, exact tokens grant that action, an empty
// set grants nothing.
func ActionInScope(action string, actions []string) bool {
	for _, a := range actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

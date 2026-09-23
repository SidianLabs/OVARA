package policy

import (
	"errors"
	"net/url"
	pathpkg "path"
	"strings"
	"sync"
)

type Rule struct {
	ActionType    string `json:"action_type"`
	Environment   string `json:"environment"`
	// Resource restricts the rule to matching request resources. Resources
	// are "METHOD scheme://host/path" for egress actions. The pattern is a
	// simple glob: '*' matches any substring, all other characters are
	// literal; an empty pattern matches every resource. Examples:
	//   "*https://api.github.com/*"  — any method to that host
	//   "GET https://pypi.org/*"     — GETs only
	Resource      string `json:"resource,omitempty"`
	Allow         bool   `json:"allow"`
	Deny          bool   `json:"deny"`
	Escalate      bool   `json:"escalate"`
	MinTrustScore *float64 `json:"min_trust_score,omitempty"` // deny if trust score below this
	MinTrustLevel string   `json:"min_trust_level,omitempty"`  // deny/escalate if trust level below this
	// RequireLease demands a valid capability lease bound to the
	// authenticated principal for this rule to allow; without one the
	// decision escalates instead of allowing.
	RequireLease bool `json:"require_lease,omitempty"`
	Conditions  map[string]interface{} `json:"conditions,omitempty"` // validator metadata (depends_on, ref)
	Description string `json:"description,omitempty"` // operator annotation — never evaluated
}

type Store struct {
	mu       sync.RWMutex
	version  string
	rules    []Rule
	filePath string
}

func NewStore(version string) *Store {
	return &Store{version: version, rules: defaultRules()}
}

func (s *Store) ClearRules() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = nil
}

func (s *Store) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) SetFilePath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filePath = path
}

// FilePath returns the configured backing file, or "" when the store is
// memory-only. Used by policy distribution to persist pushed rules.
func (s *Store) FilePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filePath
}

func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.filePath == "" {
		return errors.New("no file path set")
	}
	newStore, err := LoadStoreFromFile(s.filePath, s.version)
	if err != nil {
		return err
	}
	s.rules = newStore.rules
	s.version = newStore.version
	return nil
}

func (s *Store) RulesForAction(actionType string) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matching []Rule
	for _, r := range s.rules {
		if r.ActionType == actionType || r.ActionType == "*" {
			matching = append(matching, r)
		}
	}
	return matching
}

func (s *Store) RulesForEnvironment(env string) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matching []Rule
	for _, r := range s.rules {
		if r.Environment == env || r.Environment == "*" {
			matching = append(matching, r)
		}
	}
	return matching
}

func (s *Store) AddRule(r Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, r)
}

func (s *Store) ListRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Rule, len(s.rules))
	copy(result, s.rules)
	return result
}

func (s *Store) GetRule(actionType, environment string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if r.ActionType == actionType && r.Environment == environment {
			return r, true
		}
	}
	return Rule{}, false
}

func (s *Store) ReloadFromStore(other *Store) error {
	if other == nil {
		return errors.New("cannot reload from nil store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = other.ListRules()
	s.version = other.Version()
	return nil
}

func (s *Store) SetVersion(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version = v
}

func defaultRules() []Rule {
	return []Rule{
		{ActionType: "*", Environment: "production", Deny: false, Escalate: true},
		{ActionType: "shell", Environment: "*", Escalate: true},
		{ActionType: "exec", Environment: "*", Escalate: true},
		{ActionType: "github.merge", Environment: "*", Escalate: true},
		{ActionType: "github.delete_branch", Environment: "*", Escalate: true},
		{ActionType: "ci.deploy", Environment: "*", Escalate: true},
		{ActionType: "git.force_push", Environment: "*", Escalate: true},
	}
}

// MatchResource reports whether pattern matches resource. An empty pattern
// matches everything (rules that predate resource matching keep their
// semantics). Otherwise the resource is canonicalized FIRST — authorization
// is decided on the parsed destination, never on raw request text:
//
//   - resource form: "METHOD scheme://host[:port]/path[?query]"
//   - host is lowercased, trailing-dot-stripped; default ports (:443 https,
//     :80 http) are dropped so explicit-port and implicit-port forms match
//   - userinfo, unparseable URLs, and missing schemes never match a
//     URL-shaped pattern
//   - a host literal in the pattern matches only that host or a proper
//     subdomain suffix (label boundary) — "api.github.com.evil.com" and
//     "notgithub.com" do not match a github.com pattern
//
// Patterns containing "://" get the host-boundary check; non-URL patterns
// fall back to plain glob over the canonical string (legacy compat — write
// URL-shaped patterns for real authorization).
func MatchResource(pattern, resource string) bool {
	if pattern == "" {
		return true
	}
	if !strings.Contains(resource, "://") {
		return globMatch(pattern, resource) // non-URL resource: plain glob
	}
	canon, ok := CanonicalResource(resource)
	if !ok {
		return false // malformed/userinfo URL never matches — fail closed
	}
	return MatchCanonicalResource(pattern, canon)
}

// CanonicalResource normalizes "METHOD scheme://authority/path" into a
// canonical string. Returns ok=false for userinfo-bearing, schemeless, or
// unparseable resources.
//
// Two space-bearing forms exist:
//   - "METHOD <url>" — the method segment must be a plain method token
//     (letters only); "https://evil.com/?x= https://api.github.com/" must
//     not let the evil URL hide in the method slot and be discarded.
//   - "<url> refs/a,refs/b" — the proxy's git gate appends a ref list
//     after the URL; only a strict refs/-prefixed token may occupy that
//     slot, anything else (e.g. a second URL) is smuggling → fail.
func CanonicalResource(resource string) (string, bool) {
	method, rest := resource, ""
	if i := strings.IndexByte(resource, ' '); i > 0 {
		if !isMethodToken(resource[:i]) {
			return "", false
		}
		method, rest = strings.ToUpper(resource[:i]), strings.TrimSpace(resource[i+1:])
	}
	suffix := ""
	if i := strings.IndexByte(rest, ' '); i > 0 {
		tail := strings.TrimSpace(rest[i+1:])
		if !isRefList(tail) {
			return "", false
		}
		suffix, rest = " "+tail, rest[:i]
	}
	u, err := url.Parse(rest)
	if err != nil || u == nil || u.Scheme == "" || u.Hostname() == "" {
		return "", false
	}
	if u.User != nil {
		return "", false // userinfo never participates in authorization
	}
	// Dot segments in the DECODED path (raw or percent-encoded, e.g.
	// %2e%2e) are rejected rather than normalized: cleaning happens on
	// the escaped path, so an encoded ".." would survive canonicalization
	// as a literal segment, pass prefix-scoped checks, and only resolve
	// to a parent traversal for a downstream consumer that decodes it.
	// Fail closed at the shared canonicalizer so both policy matching
	// and delegation capability matching reject the escape.
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	clean := pathpkg.Clean("/" + strings.TrimPrefix(u.EscapedPath(), "/"))
	if strings.HasSuffix(u.EscapedPath(), "/") && clean != "/" {
		clean += "/"
	}
	var b strings.Builder
	if method != "" {
		b.WriteString(method)
		b.WriteByte(' ')
	}
	b.WriteString(scheme)
	b.WriteString("://")
	if strings.Contains(host, ":") {
		b.WriteString("[" + host + "]") // IPv6 literal
	} else {
		b.WriteString(host)
	}
	if port != "" {
		b.WriteString(":" + port)
	}
	b.WriteString(clean)
	if u.RawQuery != "" {
		b.WriteString("?" + u.RawQuery)
	}
	b.WriteString(suffix)
	return b.String(), true
}

// isMethodToken reports whether s is a bare HTTP-method-shaped token
// (letters only — GET/POST/CONNECT/…). Anything containing ':', '/',
// '@', or other punctuation is a URL fragment posing as a method.
func isMethodToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// isRefList reports whether s is a comma-separated git ref list as
// appended by the proxy's git gate ("refs/heads/main,refs/tags/v1").
func isRefList(s string) bool {
	for _, ref := range strings.Split(s, ",") {
		if !strings.HasPrefix(ref, "refs/") {
			return false
		}
		for i := 5; i < len(ref); i++ {
			c := ref[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '/' || c == '.' ||
				c == '_' || c == '-' || c == '~'
			if !ok {
				return false
			}
		}
	}
	return true
}

// MatchCanonicalResource matches a glob pattern against an already
// canonicalized resource string.
func MatchCanonicalResource(pattern, canon string) bool {
	if pattern == "" {
		return true
	}
	// Split method out of both sides — a literal method prefix is matched
	// case-insensitively; the glob itself runs on the URL part.
	canonURL := canon
	if i := strings.IndexByte(canon, ' '); i > 0 {
		canonURL = canon[i+1:]
		if j := strings.IndexByte(pattern, ' '); j > 0 && !strings.Contains(pattern[:j], "*") {
			if !strings.EqualFold(pattern[:j], canon[:i]) {
				return false
			}
			pattern = strings.TrimSpace(pattern[j+1:])
		}
	}
	if strings.Contains(pattern, "://") && !hostLiteralMatches(pattern, canonURL) {
		return false
	}
	return globMatch(pattern, canonURL)
}

// hostLiteralMatches enforces host-boundary semantics. If the pattern's
// authority begins with a literal (no leading '*'), the resource host must
// EQUAL that literal — "sub.api.github.com" does not match an
// "api.github.com" pattern. If the authority begins with '*' (e.g.
// "*.github.com" or "*github.com"), a proper ".suffix" subdomain match is
// allowed — but "github.com.evil.com" still fails because the literal must
// terminate the host at a label boundary.
func hostLiteralMatches(pattern, canonURL string) bool {
	pAuth := authoritySegment(pattern)
	if pAuth == "" {
		return true
	}
	host := canonHost(canonURL)
	if host == "" {
		return true // can't determine → let glob decide
	}
	lit := longestLiteral(pAuth)
	lit = strings.TrimSuffix(strings.ToLower(lit), ".")
	// Strip a trailing :port literal from the pattern's authority literal.
	if i := strings.LastIndex(lit, ":"); i > 0 && !strings.Contains(lit[i+1:], "]") {
		lit = lit[:i]
	}
	lit = strings.TrimPrefix(strings.TrimSuffix(lit, "]"), "[") // IPv6 brackets
	if lit == "" {
		return true
	}
	if !strings.HasPrefix(pAuth, "*") {
		return host == lit
	}
	if strings.HasPrefix(lit, ".") {
		return strings.HasSuffix(host, lit) // "*.x" → subdomains of x only
	}
	return host == lit || strings.HasSuffix(host, "."+lit)
}

func authoritySegment(urlGlob string) string {
	i := strings.Index(urlGlob, "://")
	if i < 0 {
		return ""
	}
	rest := urlGlob[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}

func canonHost(canonURL string) string {
	i := strings.Index(canonURL, "://")
	if i < 0 {
		return ""
	}
	rest := canonURL[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	if strings.HasPrefix(rest, "[") { // IPv6 literal
		if k := strings.IndexByte(rest, ']'); k >= 0 {
			return rest[1:k]
		}
	}
	if k := strings.LastIndex(rest, ":"); k >= 0 {
		return rest[:k]
	}
	return rest
}

func longestLiteral(s string) string {
	best, cur := "", ""
	for _, r := range s {
		if r == '*' {
			if len(cur) > len(best) {
				best = cur
			}
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if len(cur) > len(best) {
		best = cur
	}
	return best
}

func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		idx := strings.Index(s[pos:], p)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(p)
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(s, last) {
		return false
	}
	return true
}


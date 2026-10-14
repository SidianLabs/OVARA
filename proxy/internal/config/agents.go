package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Taint is the "untrusted read, then write" rule (proxy/internal/proxy
// taint.go). Zero fields keep the defaults.
type Taint struct {
	// On turns the rule on or off; default on.
	On *bool `json:"on,omitempty"`
	// WindowMinutes is how long a read of untrusted content marks the
	// agent (default 30).
	WindowMinutes int `json:"taint_window_minutes,omitempty"`
	// UntrustedReads are URL globs ("*" matches anything, query ignored)
	// of reads on trusted hosts that return content anyone can write:
	// issues, pull request comments, discussions. Non-nil replaces the
	// defaults.
	UntrustedReads []string `json:"untrusted_reads,omitempty"`
	// ExemptWrites are URL globs of writes that are never asked about
	// because of taint (default: npm audit). Non-nil replaces the defaults.
	ExemptWrites []string `json:"exempt_writes,omitempty"`
}

// ModelBudget is the per-agent allowance for model API use in one run.
// Zero fields keep the defaults (2000 requests, 50M input and 10M output
// tokens).
type ModelBudget struct {
	Off          bool  `json:"off,omitempty"`
	Requests     int64 `json:"requests,omitempty"`
	InputTokens  int64 `json:"input_tokens,omitempty"`
	OutputTokens int64 `json:"output_tokens,omitempty"`
}

// DefaultAgentName is how the single legacy agent_token is named in
// approvals, in `ovara kill -agent` and in `ovara agent list`.
const DefaultAgentName = "default"

// AllAgents in the revoked list stops every agent at once.
const AllAgents = "*"

var agentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidAgentName reports whether name can name an agent: lower-case
// letters, digits, "-" and "_", at most 32 characters, and not one of the
// reserved names.
func ValidAgentName(name string) error {
	if !agentNameRE.MatchString(name) {
		return fmt.Errorf("agent name %q: use 1-32 lower-case letters, digits, '-' or '_', starting with a letter or digit", name)
	}
	if name == DefaultAgentName {
		return fmt.Errorf("agent name %q is reserved for agent_token", name)
	}
	if len(name) >= 3 && name[:3] == "pt_" {
		return fmt.Errorf("agent name %q: names starting with pt_ look like token hashes in receipts", name)
	}
	return nil
}

// minAgentTokenLen keeps a hand-written token from being guessable.
const minAgentTokenLen = 32

// ValidateAgents checks the agents map: valid names, long enough tokens,
// no token used twice (or equal to agent_token), so a token names exactly
// one agent.
func ValidateAgents(agents map[string]string, legacy string) error {
	seen := map[string]string{}
	if legacy != "" {
		seen[legacy] = DefaultAgentName
	}
	names := make([]string, 0, len(agents))
	for n := range agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := ValidAgentName(n); err != nil {
			return fmt.Errorf("agents: %w", err)
		}
		t := agents[n]
		if len(t) < minAgentTokenLen {
			return fmt.Errorf("agents: the token for %q is shorter than %d characters", n, minAgentTokenLen)
		}
		if other, dup := seen[t]; dup {
			return fmt.Errorf("agents: %q and %q have the same token", other, n)
		}
		seen[t] = n
	}
	return nil
}

// NewAgentToken returns 32 random bytes, hex encoded.
func NewAgentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RevokedAgents is the file `ovara kill` writes and the proxy watches:
// stopped agent names (or "*" for all) and when they were stopped.
type RevokedAgents struct {
	Stopped map[string]time.Time `json:"stopped"`
}

// LoadRevoked reads the revoked-agents file. A missing file means no agent
// is stopped; any other failure is an error, so a caller can keep what it
// had rather than let a stopped agent back in.
func LoadRevoked(path string) (*RevokedAgents, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &RevokedAgents{Stopped: map[string]time.Time{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var r RevokedAgents
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Stopped == nil {
		r.Stopped = map[string]time.Time{}
	}
	return &r, nil
}

// Save writes the file owner-only, atomically.
func (r *RevokedAgents) Save(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// WriteFileAtomic writes data to a temporary file next to path with perm,
// syncs it and renames it over path.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadAgents returns the agents map and agent_token of a proxy.json
// without the rest of the validation Load does.
func ReadAgents(path string) (map[string]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var c struct {
		Agents     map[string]string `json:"agents"`
		AgentToken string            `json:"agent_token"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if err := ValidateAgents(c.Agents, c.AgentToken); err != nil {
		return nil, "", err
	}
	return c.Agents, c.AgentToken, nil
}

// WriteAgents replaces the agents map in a proxy.json and leaves every
// other field as it was. The file stays owner-only.
func WriteAgents(path string, agents map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(agents) == 0 {
		delete(doc, "agents")
	} else {
		raw, err := json.Marshal(agents)
		if err != nil {
			return err
		}
		doc["agents"] = raw
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(out, '\n'), 0o600)
}

// AgentScope narrows what one named agent may do at the proxy, on top of
// the policy: the resources it may act on (globs over the resource policy
// sees: "GET https://api.example.com/*", "tcp:db.internal:5432"), the
// agent it is a sub-agent of (its allow list must fit inside the parent's,
// and stopping the parent stops it too), and who it acts for (shown with
// every approval and recorded in every receipt, never used to decide).
type AgentScope struct {
	Parent string   `json:"parent,omitempty"`
	For    string   `json:"for,omitempty"`
	Allow  []string `json:"allow,omitempty"`
}

// maxScopeDepth bounds a chain of sub-agents.
const maxScopeDepth = 16

// ValidateAgentScopes checks scopes against the agents they name: every
// scoped agent exists (the legacy agent_token is "default"), a parent
// exists, is not the agent itself and makes no cycle, patterns are not
// empty, and a sub-agent's allow list fits inside its parent's.
func ValidateAgentScopes(scopes map[string]AgentScope, agents map[string]string, legacy string) error {
	exists := func(name string) bool {
		if name == DefaultAgentName && legacy != "" {
			return true
		}
		_, ok := agents[name]
		return ok
	}
	names := make([]string, 0, len(scopes))
	for n := range scopes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sc := scopes[n]
		if !exists(n) {
			return fmt.Errorf("agent_scopes: no agent named %q", n)
		}
		for _, p := range sc.Allow {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("agent_scopes: %q has an empty allow pattern", n)
			}
		}
		if len(sc.For) > 200 {
			return fmt.Errorf("agent_scopes: %q: \"for\" is longer than 200 characters", n)
		}
		if sc.Parent == "" {
			continue
		}
		if sc.Parent == n {
			return fmt.Errorf("agent_scopes: %q cannot be its own parent", n)
		}
		if !exists(sc.Parent) {
			return fmt.Errorf("agent_scopes: %q names a parent that does not exist: %q", n, sc.Parent)
		}
		// no cycles, bounded depth
		seen := map[string]bool{n: true}
		for p, depth := sc.Parent, 0; p != ""; p, depth = scopes[p].Parent, depth+1 {
			if seen[p] || depth >= maxScopeDepth {
				return fmt.Errorf("agent_scopes: the parents of %q form a cycle or go deeper than %d", n, maxScopeDepth)
			}
			seen[p] = true
		}
		if !ScopeCovers(scopes[sc.Parent].Allow, sc.Allow) {
			return fmt.Errorf("agent_scopes: %q is wider than its parent %q: every pattern of a sub-agent must fit inside one of its parent's", n, sc.Parent)
		}
	}
	return nil
}

// ScopeCovers reports whether every pattern of child fits inside some
// pattern of parent. An empty parent list is no limit and covers anything;
// an empty child list under a limited parent is refused (it would mean no
// limit). A child pattern fits a parent pattern when the parent's glob
// matches it as text, its own '*' included: a sufficient test, never a
// permissive one.
func ScopeCovers(parent, child []string) bool {
	if len(parent) == 0 {
		return true
	}
	if len(child) == 0 {
		return false
	}
	for _, c := range child {
		ok := false
		for _, p := range parent {
			if GlobMatch(p, c) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// GlobMatch matches s against pattern, where '*' matches any run of
// characters and everything else is literal.
func GlobMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// InScope reports whether resource matches one of the scope's patterns.
// A scope with no patterns allows everything (it then only names a parent
// or who the agent acts for).
func (sc AgentScope) InScope(resource string) bool {
	if len(sc.Allow) == 0 {
		return true
	}
	for _, p := range sc.Allow {
		if GlobMatch(p, resource) {
			return true
		}
	}
	return false
}

// ReadAgentScopes reads and validates the agent scopes of a proxy.json
// against the agents in the same file.
func ReadAgentScopes(path string) (map[string]AgentScope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c struct {
		Agents     map[string]string     `json:"agents"`
		AgentToken string                `json:"agent_token"`
		Scopes     map[string]AgentScope `json:"agent_scopes"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := ValidateAgentScopes(c.Scopes, c.Agents, c.AgentToken); err != nil {
		return nil, err
	}
	return c.Scopes, nil
}

// WriteAgentScopes replaces the agent_scopes map in a proxy.json and
// leaves every other field as it was.
func WriteAgentScopes(path string, scopes map[string]AgentScope) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(scopes) == 0 {
		delete(doc, "agent_scopes")
	} else {
		b, err := json.Marshal(scopes)
		if err != nil {
			return err
		}
		doc["agent_scopes"] = b
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(out, '\n'), 0o600)
}

// Flow is an information-flow rule, the confidentiality side of the taint
// rule: for WindowMinutes after the agent read from one of Sources (URL
// globs), every write that policy would let through on its own to a
// destination that matches none of Destinations (URL globs) is asked
// about (Effect "escalate", the default) or refused ("deny"). "What was
// read from X may only go to Y."
type Flow struct {
	Name          string   `json:"name"`
	Sources       []string `json:"sources"`
	Destinations  []string `json:"destinations,omitempty"`
	WindowMinutes int      `json:"window_minutes,omitempty"`
	Effect        string   `json:"effect,omitempty"`
}

// ValidateFlows checks the flow rules: a name, at least one source, an
// effect that is escalate or deny.
func ValidateFlows(flows []Flow) error {
	seen := map[string]bool{}
	for i, f := range flows {
		if f.Name == "" || len(f.Name) > 40 {
			return fmt.Errorf("flows[%d]: a name of 1 to 40 characters is needed", i)
		}
		if seen[f.Name] {
			return fmt.Errorf("flows: two rules are named %q", f.Name)
		}
		seen[f.Name] = true
		if len(f.Sources) == 0 {
			return fmt.Errorf("flows[%d] (%s): at least one source URL pattern is needed", i, f.Name)
		}
		for _, p := range append(append([]string{}, f.Sources...), f.Destinations...) {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("flows[%d] (%s): an empty pattern", i, f.Name)
			}
		}
		switch f.Effect {
		case "", "escalate", "deny":
		default:
			return fmt.Errorf("flows[%d] (%s): effect %q: use \"escalate\" or \"deny\"", i, f.Name, f.Effect)
		}
		if f.WindowMinutes < 0 {
			return fmt.Errorf("flows[%d] (%s): window_minutes must not be negative", i, f.Name)
		}
	}
	return nil
}

// DLP is the content rule on what leaves: a request a rule allowed whose
// body or query carries a secret-shaped value (a private key, a cloud or
// API key, a JWT, a card number, or one of Patterns) is asked about.
type DLP struct {
	Off      bool         `json:"off,omitempty"`
	Patterns []DLPPattern `json:"patterns,omitempty"`
	// Exempt are URL globs never scanned.
	Exempt []string `json:"exempt,omitempty"`
	// IncludeModelCalls scans the agent's model requests too. Off by
	// default: a coding agent sends the code it works on to its model, and
	// code holds key-shaped strings; turn it on where a key reaching the
	// provider is the thing to stop.
	IncludeModelCalls bool `json:"include_model_calls,omitempty"`
}

// DLPPattern is an operator's own detector: a name and a regular
// expression (RE2 syntax).
type DLPPattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

var dlpNameRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// Validate checks the custom patterns: a short lower-case name, a regular
// expression that compiles, at most 64 of them.
func (d *DLP) Validate() error {
	if d == nil {
		return nil
	}
	if len(d.Patterns) > 64 {
		return fmt.Errorf("dlp.patterns: at most 64 patterns")
	}
	for i, p := range d.Patterns {
		if !dlpNameRe.MatchString(p.Name) {
			return fmt.Errorf("dlp.patterns[%d]: the name must be 1 to 40 characters of a-z, 0-9 and _", i)
		}
		if p.Regex == "" || len(p.Regex) > 512 {
			return fmt.Errorf("dlp.patterns[%d] (%s): a regular expression of 1 to 512 characters is needed", i, p.Name)
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			return fmt.Errorf("dlp.patterns[%d] (%s): %v", i, p.Name, err)
		}
	}
	return nil
}

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

package policy

import (
	"errors"
	"fmt"
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

// MatchResource reports whether pattern matches resource. '*' matches any
// (possibly empty) substring; every other character is literal. An empty
// pattern matches everything — rules that predate resource matching keep
// their original semantics. Not anchored-optional: matching is over the
// whole string, so "github" never matches "https://api.github.com/x" unless
// written "*github*".
func MatchResource(pattern, resource string) bool {
	if pattern == "" {
		return true
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		idx := strings.Index(resource[pos:], p)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // pattern doesn't start with '*': first literal must anchor
		}
		pos += idx + len(p)
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(resource, last) {
		return false
	}
	return true
}

func LoadStoreFromConfig(cfg map[string]any) (*Store, error) {
	version, ok := cfg["policy_version"].(string)
	if !ok {
		version = "v1-default"
	}
	store := NewStore(version)
	if rulesData, ok := cfg["rules"].([]any); ok {
		for _, r := range rulesData {
			ruleMap, ok := r.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid rule format")
			}
			rule := Rule{}
			if at, ok := ruleMap["action_type"].(string); ok {
				rule.ActionType = at
			}
			if env, ok := ruleMap["environment"].(string); ok {
				rule.Environment = env
			}
			if res, ok := ruleMap["resource"].(string); ok {
				rule.Resource = res
			}
			if allow, ok := ruleMap["allow"].(bool); ok {
				rule.Allow = allow
			}
			if deny, ok := ruleMap["deny"].(bool); ok {
				rule.Deny = deny
			}
			if escalate, ok := ruleMap["escalate"].(bool); ok {
				rule.Escalate = escalate
			}
			store.AddRule(rule)
		}
	}
	return store, nil
}
package policy

import (
	"errors"
	"fmt"
	"sync"
)

type Rule struct {
	ActionType  string
	Environment string
	Allow       bool
	Deny        bool
	Escalate    bool
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

func defaultRules() []Rule {
	return []Rule{
		{ActionType: "*", Environment: "production", Deny: false, Escalate: true},
		{ActionType: "shell", Environment: "*", Escalate: true},
		{ActionType: "github.merge", Environment: "*", Escalate: true},
		{ActionType: "github.delete_branch", Environment: "*", Escalate: true},
		{ActionType: "ci.deploy", Environment: "*", Escalate: true},
		{ActionType: "git.force_push", Environment: "*", Escalate: true},
	}
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
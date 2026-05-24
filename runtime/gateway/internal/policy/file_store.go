package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

type filePolicy struct {
	Version string `json:"version"`
	Rules    []fileRule `json:"rules"`
}

type fileRule struct {
	ActionType  string `json:"action_type"`
	Environment string `json:"environment"`
	Allow       bool   `json:"allow"`
	Deny        bool   `json:"deny"`
	Escalate    bool   `json:"escalate"`
}

func LoadStoreFromFile(filePath string, versionHint string) (*Store, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var fp filePolicy
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	version := fp.Version
	if version == "" {
		version = versionHint
	}
	if version == "" {
		version = "v1-default"
	}

	rules := make([]Rule, len(fp.Rules))
	for i, fr := range fp.Rules {
		rules[i] = Rule{
			ActionType:  fr.ActionType,
			Environment: fr.Environment,
			Allow:       fr.Allow,
			Deny:        fr.Deny,
			Escalate:    fr.Escalate,
		}
	}

	store := &Store{version: version, rules: rules}
	return store, nil
}
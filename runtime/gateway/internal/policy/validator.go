package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidatePolicyData(data []byte) (*ValidationResult, error) {
	var fp filePolicy
	if err := json.Unmarshal(data, &fp); err != nil {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("invalid JSON: %v", err)},
		}, nil
	}
	return v.ValidateFilePolicy(&fp)
}

func (v *Validator) ValidateFilePolicy(fp *filePolicy) (*ValidationResult, error) {
	result := &ValidationResult{Valid: true}

	if fp.Version == "" {
		result.Errors = append(result.Errors, "policy version is required")
		result.Valid = false
	}

	if len(fp.Rules) == 0 {
		result.Warnings = append(result.Warnings, "policy has no rules - all actions will be allowed by default")
	}

	seenRules := make(map[string]int)
	for i, rule := range fp.Rules {
		if errs := v.validateRule(i, &rule, seenRules); len(errs) > 0 {
			result.Errors = append(result.Errors, errs...)
			result.Valid = false
		}
	}

	if cycles := v.DetectCatch22(fp.Rules); len(cycles) > 0 {
		for _, cycle := range cycles {
			result.Errors = append(result.Errors,
				fmt.Sprintf("circular dependency detected: %s", strings.Join(cycle, " -> ")))
		}
		result.Valid = false
	}

	if warns := v.checkContradictions(fp.Rules); len(warns) > 0 {
		result.Warnings = append(result.Warnings, warns...)
	}

	return result, nil
}

// DetectCatch22 finds circular dependencies between policy rules.
//
// A rule R1 is considered to "depend on" rule R2 if any of the following
// hold:
//
//  1. R1's `conditions.depends_on` field names R2's (action_type, environment)
//  2. R1's `conditions.ref` field names R2's identity
//  3. R1's `conditions.<custom>` field matches R2's identity pattern
//     "action_type:environment"
//
// A cycle is a path R1 -> R2 -> ... -> R1 in this dependency graph.
// Cycles produce a "catch-22" — the rules mutually depend on each other
// and can never resolve to a stable decision.
//
// Returns the list of cycles, where each cycle is the ordered list of
// rule keys forming the cycle.
func (v *Validator) DetectCatch22(rules []fileRule) [][]string {
	adjacency := make(map[string][]string)
	keyToIdx := make(map[string]int)

	for _, r := range rules {
		key := ruleKey(r)
		keyToIdx[key] = 0
		adjacency[key] = []string{}
	}

	for _, r := range rules {
		key := ruleKey(r)
		deps := extractDependencies(r)
		for _, dep := range deps {
			if _, exists := keyToIdx[dep]; exists {
				adjacency[key] = append(adjacency[key], dep)
			}
		}
	}

	// Tarjan-style SCC detection
	var cycles [][]string
	visited := make(map[string]int) // 0 = unvisited, 1 = in stack, 2 = done
	var stack []string
	onStack := make(map[string]bool)

	var dfs func(node string)
	dfs = func(node string) {
		visited[node] = 1
		stack = append(stack, node)
		onStack[node] = true

		for _, next := range adjacency[node] {
			switch visited[next] {
			case 0:
				dfs(next)
			case 1:
				// Found a back-edge → cycle
				cycleStart := -1
				for k, n := range stack {
					if n == next {
						cycleStart = k
						break
					}
				}
				if cycleStart >= 0 {
					cycle := append([]string{}, stack[cycleStart:]...)
					cycle = append(cycle, next) // close the cycle
					cycles = append(cycles, cycle)
				}
			}
		}

		onStack[node] = false
		stack = stack[:len(stack)-1]
		visited[node] = 2
	}

	for node := range adjacency {
		if visited[node] == 0 {
			dfs(node)
		}
	}

	return cycles
}

// ruleKey returns the canonical identity of a rule for graph nodes.
func ruleKey(r fileRule) string {
	return r.ActionType + ":" + r.Environment
}

// extractDependencies returns the rule keys this rule depends on,
// based on the conditions field.
func extractDependencies(r fileRule) []string {
	if r.Conditions == nil {
		return nil
	}
	var deps []string
	// depends_on: string | []string | map
	if v, ok := r.Conditions["depends_on"]; ok {
		switch val := v.(type) {
		case string:
			deps = append(deps, val)
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					deps = append(deps, s)
				}
			}
		}
	}
	// ref: string  (single dependency reference)
	if v, ok := r.Conditions["ref"]; ok {
		if s, ok := v.(string); ok {
			deps = append(deps, s)
		}
	}
	// Any condition value matching "<action>:<env>" pattern
	for _, v := range r.Conditions {
		if s, ok := v.(string); ok {
			if isRuleKey(s) {
				deps = append(deps, s)
			}
		}
	}
	return deps
}

func isRuleKey(s string) bool {
	// Heuristic: contains a colon and matches a known action or environment
	idx := strings.Index(s, ":")
	if idx < 0 || idx == len(s)-1 {
		return false
	}
	knownEnvs := map[string]bool{
		"local": true, "dev": true, "staging": true, "production": true, "*": true,
	}
	env := s[idx+1:]
	return knownEnvs[env]
}

func (v *Validator) validateRule(idx int, rule *fileRule, seen map[string]int) []string {
	var errs []string
	prefix := fmt.Sprintf("rule[%d]", idx)

	if rule.ActionType == "" {
		errs = append(errs, fmt.Sprintf("%s: action_type is required", prefix))
	}

	if rule.Environment == "" {
		errs = append(errs, fmt.Sprintf("%s: environment is required", prefix))
	}

	if !rule.Allow && !rule.Deny && !rule.Escalate {
		errs = append(errs, fmt.Sprintf("%s: rule has no effect (allow/deny/escalate all false)", prefix))
	}

	if rule.Allow && rule.Deny {
		errs = append(errs, fmt.Sprintf("%s: contradictory - allow and deny both true", prefix))
	}

	key := rule.ActionType + ":" + rule.Environment
	seen[key]++

	return errs
}

func (v *Validator) checkContradictions(rules []fileRule) []string {
	var warnings []string

	for i, r1 := range rules {
		for j, r2 := range rules {
			if i >= j {
				continue
			}
			if r1.ActionType == r2.ActionType && r1.ActionType != "*" {
				continue
			}
			if r1.Environment == r2.Environment && r1.Environment != "*" {
				continue
			}

			if r1.Allow && r2.Deny {
				warnings = append(warnings,
					fmt.Sprintf("rule[%d] allow and rule[%d] deny may conflict for action=%s env=%s",
						i, j, r1.ActionType, r1.Environment))
			}
		}
	}

	hasWildcardEnv := false
	hasSpecificEnv := false
	for _, r := range rules {
		if r.Environment == "*" {
			hasWildcardEnv = true
		} else {
			hasSpecificEnv = true
		}
	}
	if hasWildcardEnv && hasSpecificEnv {
		warnings = append(warnings, "policy mixes wildcard (*) and specific environment rules - order matters")
	}

	hasWildcardAction := false
	hasSpecificAction := false
	for _, r := range rules {
		if r.ActionType == "*" {
			hasWildcardAction = true
		} else {
			hasSpecificAction = true
		}
	}
	if hasWildcardAction && hasSpecificAction {
		warnings = append(warnings, "policy mixes wildcard (*) and specific action_type rules - order matters")
	}

	return warnings
}

func (v *Validator) ValidateRule(r *Rule) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if r.ActionType == "" {
		result.Errors = append(result.Errors, "action_type is required")
		result.Valid = false
	}

	if r.Environment == "" {
		result.Errors = append(result.Errors, "environment is required")
		result.Valid = false
	}

	if !r.Allow && !r.Deny && !r.Escalate {
		result.Errors = append(result.Errors, "rule has no effect (allow/deny/escalate all false)")
		result.Valid = false
	}

	if r.Allow && r.Deny {
		result.Errors = append(result.Errors, "contradictory - allow and deny both true")
		result.Valid = false
	}

	return result
}

func (v *Validator) ValidateRules(rules []Rule) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if len(rules) == 0 {
		result.Warnings = append(result.Warnings, "policy has no rules")
	}

	for i, r := range rules {
		if vr := v.ValidateRule(&r); !vr.Valid {
			for _, e := range vr.Errors {
				result.Errors = append(result.Errors, fmt.Sprintf("rule[%d]: %s", i, e))
			}
			result.Valid = false
		}
	}

	return result
}

func (v *Validator) FormatErrors(result *ValidationResult) string {
	if result.Valid && len(result.Warnings) == 0 {
		return "Policy is valid"
	}
	var lines []string
	if !result.Valid {
		lines = append(lines, "ERRORS:")
		for _, e := range result.Errors {
			lines = append(lines, "  - "+e)
		}
	}
	if len(result.Warnings) > 0 {
		lines = append(lines, "WARNINGS:")
		for _, w := range result.Warnings {
			lines = append(lines, "  - "+w)
		}
	}
	return strings.Join(lines, "\n")
}

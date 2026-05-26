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

	if warns := v.checkContradictions(fp.Rules); len(warns) > 0 {
		result.Warnings = append(result.Warnings, warns...)
	}

	return result, nil
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

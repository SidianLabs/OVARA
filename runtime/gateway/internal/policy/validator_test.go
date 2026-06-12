package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestValidator_ValidatePolicyData_ValidPolicy(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "shell", "environment": "local", "allow": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid policy, got errors: %v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got: %v", result.Errors)
	}
}

func TestValidator_ValidatePolicyData_InvalidJSON(t *testing.T) {
	v := NewValidator()

	data := []byte(`{invalid json}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid for bad JSON")
	}
	if len(result.Errors) == 0 {
		t.Errorf("expected at least one error for bad JSON")
	}
}

func TestValidator_ValidatePolicyData_MissingVersion(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"rules": [
			{"action_type": "shell", "environment": "local", "allow": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid for missing version")
	}
	if len(result.Errors) < 1 {
		t.Errorf("expected at least one error")
	}
}

func TestValidator_ValidatePolicyData_EmptyRules(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-empty",
		"rules": []
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid (warnings only) for empty rules")
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected at least one warning for empty rules")
	}
}

func TestValidator_ValidatePolicyData_EmptyRuleFields(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "", "environment": "local", "allow": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid for empty action_type")
	}
}

func TestValidator_ValidatePolicyData_NoEffectRule(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "shell", "environment": "local"}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid for no-effect rule")
	}
}

func TestValidator_ValidatePolicyData_ContradictoryRule(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "shell", "environment": "local", "allow": true, "deny": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Errorf("expected invalid for allow+deny rule")
	}
}

func TestValidator_ValidatePolicyData_WildcardWarnings(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "*", "environment": "*", "allow": true},
			{"action_type": "shell", "environment": "local", "allow": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected wildcard warnings")
	}
}

func TestValidator_ValidateRule_Valid(t *testing.T) {
	v := NewValidator()

	rule := &Rule{ActionType: "shell", Environment: "local", Allow: true}
	result := v.ValidateRule(rule)
	if !result.Valid {
		t.Errorf("expected valid rule: %v", result.Errors)
	}
}

func TestValidator_ValidateRule_EmptyActionType(t *testing.T) {
	v := NewValidator()

	rule := &Rule{ActionType: "", Environment: "local", Allow: true}
	result := v.ValidateRule(rule)
	if result.Valid {
		t.Errorf("expected invalid for empty action_type")
	}
}

func TestValidator_ValidateRule_EmptyEnvironment(t *testing.T) {
	v := NewValidator()

	rule := &Rule{ActionType: "shell", Environment: "", Allow: true}
	result := v.ValidateRule(rule)
	if result.Valid {
		t.Errorf("expected invalid for empty environment")
	}
}

func TestValidator_ValidateRule_NoEffect(t *testing.T) {
	v := NewValidator()

	rule := &Rule{ActionType: "shell", Environment: "local"}
	result := v.ValidateRule(rule)
	if result.Valid {
		t.Errorf("expected invalid for no-effect rule")
	}
}

func TestValidator_ValidateRule_Contradictory(t *testing.T) {
	v := NewValidator()

	rule := &Rule{ActionType: "shell", Environment: "local", Allow: true, Deny: true}
	result := v.ValidateRule(rule)
	if result.Valid {
		t.Errorf("expected invalid for contradictory rule")
	}
}

func TestValidator_ValidateRules(t *testing.T) {
	v := NewValidator()

	rules := []Rule{
		{ActionType: "shell", Environment: "local", Allow: true},
		{ActionType: "git.pull", Environment: "*", Allow: true},
	}
	result := v.ValidateRules(rules)
	if !result.Valid {
		t.Errorf("expected valid: %v", result.Errors)
	}
}

func TestValidator_ValidateRules_Empty(t *testing.T) {
	v := NewValidator()

	rules := []Rule{}
	result := v.ValidateRules(rules)
	if len(result.Warnings) == 0 {
		t.Errorf("expected warning for empty rules")
	}
}

func TestValidator_FormatErrors(t *testing.T) {
	v := NewValidator()

	validResult := &ValidationResult{Valid: true, Warnings: []string{"some warning"}}
	output := v.FormatErrors(validResult)
	if output == "" {
		t.Errorf("expected non-empty output for result with warnings")
	}

	invalidResult := &ValidationResult{Valid: false, Errors: []string{"error1", "error2"}}
	output = v.FormatErrors(invalidResult)
	if output == "" {
		t.Errorf("expected non-empty output for invalid result")
	}
}

func TestValidator_ValidatePolicyData_RealPolicyFile(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{"action_type": "ci.build_trigger", "environment": "*", "allow": true},
			{"action_type": "git.pull", "environment": "*", "allow": true},
			{"action_type": "shell", "environment": "production", "escalate": true},
			{"action_type": "shell", "environment": "dev", "escalate": true},
			{"action_type": "git.force_push", "environment": "*", "escalate": true},
			{"action_type": "github.merge", "environment": "*", "escalate": true},
			{"action_type": "*", "environment": "production", "escalate": true}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid policy, got errors: %v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got: %v", result.Errors)
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for wildcard/specific mix")
	}
}

func TestValidator_RoundTrip(t *testing.T) {
	v := NewValidator()

	original := &filePolicy{
		Version: "v1-roundtrip",
		Rules: []fileRule{
			{ActionType: "shell", Environment: "local", Allow: true},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid after roundtrip: %v", result.Errors)
	}
}

func TestValidator_DetectCatch22_NoCatch22(t *testing.T) {
	v := NewValidator()

	rules := []fileRule{
		{ActionType: "shell", Environment: "local", Allow: true},
		{ActionType: "shell", Environment: "dev", Escalate: true},
		{ActionType: "git.pull", Environment: "*", Allow: true},
	}
	cycles := v.DetectCatch22(rules)
	if len(cycles) != 0 {
		t.Errorf("expected no cycles, got: %v", cycles)
	}
}

func TestValidator_DetectCatch22_SelfLoop(t *testing.T) {
	v := NewValidator()

	// A rule whose conditions reference its own action_type + environment
	// creates a self-loop in the dependency graph
	rules := []fileRule{
		{
			ActionType:  "shell",
			Environment: "dev",
			Escalate:    true,
			Conditions:  map[string]interface{}{"ref": "shell:dev"},
		},
	}
	cycles := v.DetectCatch22(rules)
	if len(cycles) == 0 {
		t.Error("expected at least one cycle for self-loop, got none")
	}
}

func TestValidator_DetectCatch22_MutualReference(t *testing.T) {
	v := NewValidator()

	// Two rules that reference each other's outcomes
	rules := []fileRule{
		{
			ActionType:  "shell",
			Environment: "dev",
			Escalate:    true,
			Conditions:  map[string]interface{}{"depends_on": "git.push:dev"},
		},
		{
			ActionType:  "git.push",
			Environment: "dev",
			Escalate:    true,
			Conditions:  map[string]interface{}{"depends_on": "shell:dev"},
		},
	}
	cycles := v.DetectCatch22(rules)
	if len(cycles) == 0 {
		t.Error("expected at least one cycle for mutual reference, got none")
	}
}

func TestValidator_DetectCatch22_ThreeWayCycle(t *testing.T) {
	v := NewValidator()

	rules := []fileRule{
		{
			ActionType:  "shell",
			Environment: "dev",
			Conditions:  map[string]interface{}{"depends_on": "exec:dev"},
		},
		{
			ActionType:  "exec",
			Environment: "dev",
			Conditions:  map[string]interface{}{"depends_on": "git.push:dev"},
		},
		{
			ActionType:  "git.push",
			Environment: "dev",
			Conditions:  map[string]interface{}{"depends_on": "shell:dev"},
		},
	}
	cycles := v.DetectCatch22(rules)
	if len(cycles) == 0 {
		t.Error("expected at least one cycle for 3-way cycle, got none")
	}
}

func TestValidator_DetectCatch22_EmptyRules(t *testing.T) {
	v := NewValidator()
	cycles := v.DetectCatch22([]fileRule{})
	if len(cycles) != 0 {
		t.Errorf("expected no cycles for empty rules, got: %v", cycles)
	}
}

func TestValidator_ValidatePolicyData_DetectsCatch22(t *testing.T) {
	v := NewValidator()

	data := []byte(`{
		"version": "v1-test",
		"rules": [
			{
				"action_type": "shell",
				"environment": "dev",
				"escalate": true,
				"conditions": {"depends_on": "shell:dev"}
			}
		]
	}`)

	result, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected invalid for catch-22 policy")
	}
	hasCircularError := false
	for _, e := range result.Errors {
		if contains(e, "circular") {
			hasCircularError = true
			break
		}
	}
	if !hasCircularError {
		t.Errorf("expected circular dependency error, got: %v", result.Errors)
	}
}

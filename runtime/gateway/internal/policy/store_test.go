package policy

import (
	"testing"
)

func TestStore_RulesForAction(t *testing.T) {
	store := NewStore("v1")

	rules := store.RulesForAction("shell")
	if len(rules) == 0 {
		t.Error("expected rules for shell action")
	}
}

func TestStore_RulesForEnvironment(t *testing.T) {
	store := NewStore("v1")

	rules := store.RulesForEnvironment("local")
	if len(rules) == 0 {
		t.Error("expected rules for local environment")
	}
}

func TestStore_AddRule(t *testing.T) {
	store := NewStore("v1")
	initial := len(store.rules)

	store.AddRule(Rule{ActionType: "custom.action", Environment: "*", Allow: true})
	if len(store.rules) != initial+1 {
		t.Error("rule was not added")
	}
}

func TestLoadStoreFromConfig(t *testing.T) {
	cfg := map[string]any{
		"policy_version": "custom-v1",
		"rules": []any{
			map[string]any{
				"action_type": "shell",
				"environment": "production",
				"deny":        true,
			},
		},
	}

	store, err := LoadStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Version() != "custom-v1" {
		t.Errorf("version = %v, want custom-v1", store.Version())
	}
}

func TestPolicy_RuleTypes(t *testing.T) {
	r := Rule{ActionType: "shell", Environment: "local", Deny: true}
	if !r.Deny {
		t.Error("expected deny rule")
	}

	r2 := Rule{ActionType: "github.merge", Environment: "*", Escalate: true}
	if !r2.Escalate {
		t.Error("expected escalate rule")
	}
}
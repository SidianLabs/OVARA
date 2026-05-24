package policy

import (
	"os"
	"testing"
)

func TestLoadStoreFromFile_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	policyJSON := `{
		"version": "v1-test",
		"rules": [
			{"action_type": "shell", "environment": "production", "escalate": true},
			{"action_type": "github.merge", "environment": "*", "escalate": true}
		]
	}`
	if err := os.WriteFile(policyFile, []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadStoreFromFile(policyFile, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if store.Version() != "v1-test" {
		t.Errorf("expected version v1-test, got %s", store.Version())
	}
	rules := store.RulesForAction("shell")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule for shell, got %d", len(rules))
	}
	if !rules[0].Escalate {
		t.Error("expected shell rule to escalate")
	}
}

func TestLoadStoreFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	if err := os.WriteFile(policyFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadStoreFromFile(policyFile, "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadStoreFromFile_FileNotFound(t *testing.T) {
	_, err := LoadStoreFromFile("/nonexistent/policy.json", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
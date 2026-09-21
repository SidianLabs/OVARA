package policy

import (
	"os"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
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

func TestLoadStoreFromFile_AllowRules(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	policyJSON := `{
		"version": "v1-allow-test",
		"rules": [
			{"action_type": "shell", "environment": "local", "allow": true},
			{"action_type": "shell", "environment": "production", "deny": true},
			{"action_type": "shell", "environment": "dev", "escalate": true},
			{"action_type": "git.pull", "environment": "*", "allow": true}
		]
	}`
	if err := os.WriteFile(policyFile, []byte(policyJSON), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadStoreFromFile(policyFile, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if store.Version() != "v1-allow-test" {
		t.Errorf("expected version v1-allow-test, got %s", store.Version())
	}

	rules := store.RulesForAction("shell")
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules for shell, got %d", len(rules))
	}

	for _, r := range rules {
		if r.ActionType != "shell" {
			continue
		}
		if r.Environment == "local" && !r.Allow {
			t.Error("expected shell/local rule to have allow=true")
		}
		if r.Environment == "production" && !r.Deny {
			t.Error("expected shell/production rule to have deny=true")
		}
		if r.Environment == "dev" && !r.Escalate {
			t.Error("expected shell/dev rule to have escalate=true")
		}
	}

	pullRules := store.RulesForAction("git.pull")
	if len(pullRules) != 1 {
		t.Fatalf("expected 1 rule for git.pull, got %d", len(pullRules))
	}
	if !pullRules[0].Allow {
		t.Error("expected git.pull rule to have allow=true")
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

func TestWatcher_EventsOnFileChange(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := tmpDir + "/policy.json"

	initialPolicy := `{"version": "v1-initial", "rules": []}`
	if err := os.WriteFile(policyFile, []byte(initialPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	store, err := LoadStoreFromFile(policyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	store.SetFilePath(policyFile)

	source := NewLocalFileSource(policyFile, "", store)
	watcher, err := NewWatcher(source)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	if err := watcher.Watch(policyFile); err != nil {
		t.Fatal(err)
	}

	updatedPolicy := `{"version": "v2-updated", "rules": [{"action_type": "shell", "environment": "*", "escalate": true}]}`
	if err := os.WriteFile(policyFile, []byte(updatedPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-watcher.Events():
		if event.Has(fsnotify.Write) {
			if err := watcher.Reload(); err != nil {
				t.Fatalf("reload failed: %v", err)
			}
			if store.Version() != "v2-updated" {
				t.Errorf("expected v2-updated, got %s", store.Version())
			}
			return
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for fsnotify event")
	}
}

// Red-team V2/V3: a scoped rule must never silently widen to a global
// allow via JSON edge cases the standard decoder erases.
func TestParseStore_Strictness(t *testing.T) {
	scoped := `{"action_type":"http.request","environment":"*","resource":"*https://api.github.com/*","allow":true}`

	cases := []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{"resource null widens", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resource":null,"allow":true}` + `]}`, true},
		{"duplicate resource last-empty", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resource":"*https://api.github.com/*","resource":"","allow":true}` + `]}`, true},
		{"duplicate resource last-star", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resource":"*https://api.github.com/*","resource":"*","allow":true}` + `]}`, true},
		{"unknown field", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resources":"*","allow":true}` + `]}`, true},
		{"legit scoped rule parses", `{"version":"v1","rules":[` + scoped + `]}`, false},
		{"explicit star resource parses", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resource":"*","allow":true}` + `]}`, false},
		{"resource omitted parses", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","allow":true}` + `]}`, false},
		{"nested conditions object ok", `{"version":"v1","rules":[` +
			`{"action_type":"http.request","environment":"*","resource":"*","allow":true,"conditions":{"max_severity":"high"}}` + `]}`, false},
	}
	for _, c := range cases {
		_, err := ParseStore([]byte(c.doc), "")
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Agent scopes: a sub-agent's allow list fits inside its parent's, names
// resolve, no cycles; the glob test is sufficient, never permissive.

func TestValidateAgentScopes(t *testing.T) {
	agents := map[string]string{"parent": strings.Repeat("a", 32), "child": strings.Repeat("b", 32), "other": strings.Repeat("c", 32)}
	ok := map[string]AgentScope{
		"parent": {Allow: []string{"GET https://api.example.com/*", "tcp:db.internal:*"}, For: "alice@example.com"},
		"child":  {Parent: "parent", Allow: []string{"GET https://api.example.com/repos/*", "tcp:db.internal:5432"}},
		"other":  {Parent: "default"},
	}
	if err := ValidateAgentScopes(ok, agents, "legacy-token-long-enough-xxxxxxxx"); err != nil {
		t.Fatalf("valid scopes refused: %v", err)
	}
	bad := map[string]map[string]AgentScope{
		"unknown agent":   {"nobody": {Allow: []string{"GET *"}}},
		"unknown parent":  {"child": {Parent: "ghost"}},
		"self parent":     {"child": {Parent: "child"}},
		"cycle":           {"child": {Parent: "parent"}, "parent": {Parent: "child"}},
		"wider child":     {"parent": {Allow: []string{"GET https://api.example.com/*"}}, "child": {Parent: "parent", Allow: []string{"POST https://api.example.com/*"}}},
		"wildcard child":  {"parent": {Allow: []string{"GET https://api.example.com/*"}}, "child": {Parent: "parent", Allow: []string{"GET https://*/x"}}},
		"unlimited child": {"parent": {Allow: []string{"GET https://api.example.com/*"}}, "child": {Parent: "parent"}},
		"empty pattern":   {"parent": {Allow: []string{""}}},
	}
	for name, scopes := range bad {
		if err := ValidateAgentScopes(scopes, agents, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A parent without a limit covers anything; the default agent needs the legacy token.
	if err := ValidateAgentScopes(map[string]AgentScope{"other": {Parent: "default"}}, agents, ""); err == nil {
		t.Error("default without agent_token accepted as a parent")
	}
}

func TestScopeCoversAndInScope(t *testing.T) {
	if !ScopeCovers(nil, []string{"anything"}) || ScopeCovers([]string{"GET https://a/*"}, nil) {
		t.Error("an unlimited parent covers anything; an unlimited child under a limited parent does not fit")
	}
	if !ScopeCovers([]string{"GET https://*.example.com/*"}, []string{"GET https://api.example.com/*"}) {
		t.Error("a narrower host pattern fits")
	}
	if ScopeCovers([]string{"GET https://api.example.com/repos/*"}, []string{"GET https://api.example.com/*"}) {
		t.Error("a wider path pattern must not fit")
	}
	sc := AgentScope{Allow: []string{"GET https://api.example.com/*", "tcp:db.internal:5432"}}
	for res, want := range map[string]bool{"GET https://api.example.com/x": true, "POST https://api.example.com/x": false, "tcp:db.internal:5432": true, "tcp:db.internal:5433": false} {
		if sc.InScope(res) != want {
			t.Errorf("InScope(%s) = %v", res, !want)
		}
	}
	if !(AgentScope{For: "x"}).InScope("anything") {
		t.Error("a scope with no patterns limits nothing")
	}
}

func TestReadWriteAgentScopes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.json")
	doc := map[string]any{"gateway_url": "http://127.0.0.1:8080", "agents": map[string]string{"a": strings.Repeat("a", 32), "b": strings.Repeat("b", 32)}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	scopes := map[string]AgentScope{"b": {Parent: "a", For: "ops", Allow: []string{"GET https://x/*"}}}
	if err := WriteAgentScopes(path, scopes); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAgentScopes(path)
	if err != nil || got["b"].Parent != "a" || got["b"].For != "ops" || len(got["b"].Allow) != 1 {
		t.Fatalf("read back %v (%v)", got, err)
	}
	agents, _, err := ReadAgents(path)
	if err != nil || len(agents) != 2 {
		t.Fatalf("the agents were disturbed: %v %v", agents, err)
	}
	// A file whose scopes do not validate is refused as a whole.
	scopes["b"] = AgentScope{Parent: "ghost"}
	if err := WriteAgentScopes(path, scopes); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAgentScopes(path); err == nil {
		t.Fatal("invalid scopes read without error")
	}
}

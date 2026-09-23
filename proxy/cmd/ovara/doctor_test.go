package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func statuses(checks []check) map[string]string {
	m := make(map[string]string, len(checks))
	for _, c := range checks {
		m[c.name] = c.status
	}
	return m
}

func TestDoctor_FreshInit(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	checks := statuses(auditDeployment(dir))
	for name, st := range checks {
		if st == "FAIL" {
			t.Errorf("fresh init must not FAIL any check, %s failed", name)
		}
	}
	if checks["config.json"] != "PASS" || checks["auth"] != "PASS" || checks["receipt signing key"] != "PASS" {
		t.Errorf("expected core checks PASS on fresh init: %v", checks)
	}
	if checks["durable state"] != "WARN" {
		t.Errorf("expected durable-state WARN for memory-mode init, got %s", checks["durable state"])
	}
}

func TestDoctor_MissingConfig(t *testing.T) {
	checks := auditDeployment(filepath.Join(t.TempDir(), "nope"))
	if len(checks) != 1 || checks[0].status != "FAIL" {
		t.Fatalf("missing config.json must produce a single FAIL, got %+v", checks)
	}
}

func TestDoctor_LiteralSecret(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	// Inject a literal token into proxy.json
	raw, err := os.ReadFile(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["credentials"] = append(cfg["credentials"].([]any), map[string]any{
		"host": "evil.example.com", "headers": map[string]any{"Authorization": "Bearer sk-proj-secret"},
	})
	out, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range auditDeployment(dir) {
		if c.status == "FAIL" {
			found = true
		}
	}
	if !found {
		t.Error("literal secret in proxy.json must FAIL the audit")
	}
}

func TestLooksLikeSecret(t *testing.T) {
	for v, want := range map[string]bool{
		"Bearer ${GITHUB_TOKEN}":          false,
		"${ANTHROPIC_API_KEY}":            false,
		"2023-06-01":                     false,
		"Bearer sk-proj-abc123":          true,
		"ghp_abcdefghijklmnop":           true,
		"xoxb-123-456-abc":               true,
		"AKIAIOSFODNN7EXAMPLE":           true,
		"Bearer averylongliteralvalue1":  true,
	} {
		if got := looksLikeSecret(v); got != want {
			t.Errorf("looksLikeSecret(%q) = %v, want %v", v, got, want)
		}
	}
}

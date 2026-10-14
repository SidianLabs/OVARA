package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ovara.proxy/internal/config"
)

func TestPresetForAgentCommand(t *testing.T) {
	for argv0, want := range map[string]string{
		"opencode": "opencode", "/usr/local/bin/opencode": "opencode", `C:\tools\opencode.exe`: "opencode",
		"claude": "claude", "codex": "codex", "Codex": "codex",
	} {
		p, ok := presetFor(argv0)
		if !ok || p.Name != want {
			t.Errorf("%q: %v %q", argv0, ok, p.Name)
		}
	}
	for _, argv0 := range []string{"python3", "sh", "", "opencode-ai"} {
		if _, ok := presetFor(argv0); ok {
			t.Errorf("%q: should have no preset", argv0)
		}
	}
}

// Applying a preset adds its rules and model hosts once, keeps a person's
// existing rules, and marks what it added so it can be recognised.
func TestApplyPresetAddsRulesOnce(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	p, _ := presetNamed("opencode")
	added, err := applyPreset(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 3 {
		t.Fatalf("added %v", added)
	}
	if again, err := applyPreset(dir, p); err != nil || len(again) != 0 {
		t.Fatalf("second application: %v %v", again, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	var policy struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range policy.Rules {
		if d, _ := r["description"].(string); len(d) >= len(presetMarker(p)) && d[:len(presetMarker(p))] == presetMarker(p) {
			n++
			if r["allow"] != true || r["action_type"] != "http.request" {
				t.Errorf("preset rule %v", r)
			}
		}
	}
	if n != 3 {
		t.Fatalf("%d marked rules, want 3", n)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.anthropic.com", "api.openai.com", "opencode.ai"}
	if len(cfg.ModelHosts) != len(want) {
		t.Fatalf("model_hosts %v, want %v", cfg.ModelHosts, want)
	}
	for i := range want {
		if cfg.ModelHosts[i] != want[i] {
			t.Fatalf("model_hosts %v, want %v", cfg.ModelHosts, want)
		}
	}
	// A preset with nothing to add changes nothing.
	c, _ := presetNamed("claude")
	if added, err := applyPreset(dir, c); err != nil || len(added) != 0 {
		t.Fatalf("claude preset: %v %v", added, err)
	}
}

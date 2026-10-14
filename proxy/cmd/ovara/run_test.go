package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentProcessEnvReplacesOvarasVariablesAndDropsSecrets(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin", "HOME=/home/me",
		"HTTPS_PROXY=http://corp:3128", "no_proxy=api.anthropic.com", // the shell's, replaced
		"GITHUB_TOKEN=ghp_real", "AWS_SECRET_ACCESS_KEY=x", // secrets, dropped
		"EDITOR=vi",
	}
	vars := []envVar{{"HTTPS_PROXY", "http://agent:t@127.0.0.1:9443", ""}, {"NO_PROXY", "127.0.0.1,localhost", ""}, {"no_proxy", "127.0.0.1,localhost", ""}, {"GITHUB_TOKEN", keyPlaceholder, ""}}
	got := agentProcessEnv(environ, vars)
	env := map[string]string{}
	for _, kv := range got {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := env[k]; dup {
			t.Fatalf("%s twice in %v", k, got)
		}
		env[k] = v
	}
	for k, want := range map[string]string{"PATH": "/usr/bin", "HOME": "/home/me", "EDITOR": "vi",
		"HTTPS_PROXY": "http://agent:t@127.0.0.1:9443", "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost", "GITHUB_TOKEN": keyPlaceholder} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	if _, ok := env["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Error("a secret the shell had reached the agent")
	}
	if strings.Contains(strings.Join(got, "\n"), "ghp_real") || strings.Contains(strings.Join(got, "\n"), "corp:3128") {
		t.Errorf("the shell's values survived: %v", got)
	}
}

func TestRunPresetSelection(t *testing.T) {
	if p, ok, err := runPreset("/opt/bin/opencode", "auto"); err != nil || !ok || p.Name != "opencode" {
		t.Fatalf("auto: %v %v %v", p, ok, err)
	}
	if _, ok, err := runPreset("python3", "auto"); err != nil || ok {
		t.Fatalf("auto, unknown program: %v %v", ok, err)
	}
	if _, ok, err := runPreset("opencode", "none"); err != nil || ok {
		t.Fatalf("none: %v %v", ok, err)
	}
	if p, ok, err := runPreset("python3", "codex"); err != nil || !ok || p.Name != "codex" {
		t.Fatalf("by name: %v %v %v", p, ok, err)
	}
	if _, _, err := runPreset("x", "nope"); err == nil || !strings.Contains(err.Error(), "opencode") {
		t.Fatalf("unknown name: %v", err)
	}
}

// `ovara run -dir D -- sh -c ...` starts Ovara, runs the command with
// Ovara's environment, stops when it exits and exits with its status. The
// opencode preset is applied, so the gateway loads a policy with preset
// rules in it.
func TestRunWithACommandStartsOvaraAroundIt(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a gateway")
	}
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "seen.txt")
	script := `printf '%s\n%s\n%s\n' "$HTTPS_PROXY" "$NO_PROXY" "$NODE_EXTRA_CA_CERTS" > ` + out + `; exit 3`
	err := cmdRun([]string{"-dir", dir, "-no-ui", "-preset", "opencode", "--", "sh", "-c", script})
	var ae *agentExit
	if err == nil || !errors.As(err, &ae) || ae.code != 3 {
		t.Fatalf("want the agent's status 3, got %v", err)
	}
	seen, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatal(rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(seen)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "http://agent:") || !strings.Contains(lines[0], "@127.0.0.1:9443") {
		t.Fatalf("HTTPS_PROXY seen by the agent: %q", lines)
	}
	if lines[1] != "127.0.0.1,localhost" || !strings.HasSuffix(lines[2], filepath.Join("var", "ca.pem")) {
		t.Fatalf("NO_PROXY / CA seen by the agent: %q", lines)
	}
	policy, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	if !strings.Contains(string(policy), "[preset opencode]") {
		t.Fatal("the preset was not applied")
	}
}

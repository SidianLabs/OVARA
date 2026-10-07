package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/creds"
)

// The env printed by `ovara env` must actually work against a deployment
// written by `ovara init`: the proxy URL carries the agent token (the proxy
// rejects requests without it), every CA variable points at the CA file,
// and every bound key gets a placeholder, never a real value.
func TestAgentEnv_FromInitDeployment(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "ghp_REAL_SECRET")
	vars, notes, err := agentEnv(dir, cfg, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vars {
		got[v.name] = v.value
	}
	if want := "http://agent:" + cfg.AgentToken + "@127.0.0.1:9443"; got["HTTPS_PROXY"] != want {
		t.Fatalf("HTTPS_PROXY = %q, want %q", got["HTTPS_PROXY"], want)
	}
	ca := filepath.Join(dir, "var", "ca.pem")
	for _, name := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		if got[name] != ca {
			t.Errorf("%s = %q, want %q", name, got[name], ca)
		}
	}
	// Before `ovara run` has recorded which keys it injects: no placeholders.
	if _, ok := got["GITHUB_TOKEN"]; ok {
		t.Error("placeholder emitted before ovara run recorded active keys")
	}
	if len(notes) < 2 {
		t.Errorf("expected notes about the missing CA and placeholders, got %v", notes)
	}

	// `ovara run` injects only GitHub (the only key set in its env):
	// the agent gets a GitHub placeholder and nothing for Anthropic, so a
	// Claude Code subscription login keeps working.
	_, skipped := creds.LoadReport(cfg.Credentials)
	if err := writeActiveKeys(dir, cfg.Credentials, skipped); err != nil {
		t.Fatal(err)
	}
	vars, _, err = agentEnv(dir, cfg, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]string{}
	for _, v := range vars {
		got[v.name] = v.value
	}
	if got["GITHUB_TOKEN"] != keyPlaceholder {
		t.Errorf("GITHUB_TOKEN = %q, want placeholder", got["GITHUB_TOKEN"])
	}
	if _, ok := got["ANTHROPIC_API_KEY"]; ok {
		t.Error("ANTHROPIC_API_KEY placeholder set although Ovara does not inject it")
	}
	for _, v := range vars {
		if strings.Contains(v.value, "REAL_SECRET") {
			t.Fatalf("real key leaked into agent env via %s", v.name)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, activeKeysFile))
	if strings.Contains(string(raw), "REAL_SECRET") {
		t.Fatal("active-keys file must hold names only")
	}
}

func TestWriteEnv_Shells(t *testing.T) {
	vars := []envVar{{"A", "it's", "c"}}
	cases := map[string]string{
		"bash":       `export A='it'\''s'`,
		"powershell": `$env:A = 'it''s'`,
		"cmd":        `set "A=it's"`,
	}
	for sh, want := range cases {
		var b bytes.Buffer
		if err := writeEnv(&b, sh, vars, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: missing %q in\n%s", sh, want, b.String())
		}
	}
	if err := writeEnv(&bytes.Buffer{}, "fish", vars, nil); err == nil {
		t.Error("unknown shell must error")
	}
}

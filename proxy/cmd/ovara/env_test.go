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
	if got["NODE_USE_ENV_PROXY"] != "1" {
		t.Error("NODE_USE_ENV_PROXY=1 missing: Node fetch() would bypass the proxy")
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
	_, skipped, _ := creds.LoadReport(cfg.Credentials)
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

// A shell often carries a NO_PROXY list (corporate setups, CI images, and
// the sandbox this was found in). The hosts on it are contacted directly, so
// an agent that inherits it goes around Ovara for them: no decision and no
// receipt, although the environment says every request goes through Ovara.
// `ovara env` replaces it with loopback only, as `ovara box` does, and says
// what it replaced.
func TestAgentEnv_PinsNoProxyToLoopback(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, inherited := range map[string]string{
		"hosts":         "localhost,127.0.0.1,api.anthropic.com,registry.npmjs.org,.corp.example,10.0.0.0/8",
		"upper only":    "api.anthropic.com",
		"loopback only": "localhost,127.0.0.1,::1",
		"nothing":       "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("NO_PROXY", inherited)
			t.Setenv("no_proxy", "")
			if name != "upper only" {
				t.Setenv("no_proxy", inherited)
			}
			vars, notes, err := agentEnv(dir, cfg, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, v := range vars {
				got[v.name] = v.value
			}
			for _, n := range []string{"NO_PROXY", "no_proxy"} {
				if got[n] != "127.0.0.1,localhost" {
					t.Errorf("%s = %q, want loopback only", n, got[n])
				}
			}
			var note string
			for _, n := range notes {
				if strings.Contains(n, "NO_PROXY") {
					note = n
				}
			}
			switch {
			case strings.Contains(inherited, "anthropic"):
				if !strings.Contains(note, "api.anthropic.com") || strings.Contains(note, "\n") {
					t.Errorf("the note should name the hosts it replaced on one line, got %q", note)
				}
			default:
				if note != "" {
					t.Errorf("nothing was replaced, yet a note says %q", note)
				}
			}
			// every shell prints the pinned value
			for _, sh := range []string{"bash", "powershell", "cmd"} {
				var b bytes.Buffer
				if err := writeEnv(&b, sh, vars, notes); err != nil {
					t.Fatal(err)
				}
				// the lines that set it, not the note that names what it replaced
				var set []string
				for _, line := range strings.Split(b.String(), "\n") {
					if strings.Contains(strings.ToUpper(line), "NO_PROXY") && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "rem") {
						set = append(set, line)
					}
				}
				if len(set) != 2 {
					t.Fatalf("%s: %d lines set NO_PROXY, want 2 (upper and lower case):\n%s", sh, len(set), b.String())
				}
				for _, l := range set {
					if !strings.Contains(l, "127.0.0.1,localhost") || strings.Contains(l, "npmjs") || strings.Contains(l, "anthropic") {
						t.Errorf("%s: %q is not loopback only", sh, l)
					}
				}
			}
		})
	}
}

// The environment is written into a stream that is eval'd, and the note quotes
// the list it replaced: a value with a line break or shell syntax in it must
// not turn into a command.
func TestAgentEnv_NoProxyNoteCannotInjectCommands(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "8080", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NO_PROXY", "good.example,\ntouch /tmp/pwned\n,$(id),`id`,a b,;rm -rf ~")
	t.Setenv("no_proxy", "")
	vars, notes, err := agentEnv(dir, cfg, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := writeEnv(&b, "bash", vars, notes); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(b.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "export ") {
			continue
		}
		t.Errorf("a line that is neither a comment nor an export: %q", line)
	}
	if strings.Contains(b.String(), "$(id)") || strings.Contains(b.String(), "`id`") || strings.Contains(b.String(), "pwned") {
		t.Errorf("hostile list entries reached the output:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "good.example") {
		t.Errorf("the ordinary host should still be named:\n%s", b.String())
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

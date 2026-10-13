package main

import (
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

// CR-02: reads that would hand the agent secrets or account data through
// the injected GitHub token pause; ordinary repository reads stay free.
func TestDefaultPolicy_SensitiveGitHubReadsEscalate(t *testing.T) {
	for _, p := range []string{
		"/repos/o/r/secret-scanning/alerts",
		"/orgs/o/secret-scanning/alerts",
		"/repos/o/r/actions/secrets",
		"/repos/o/r/actions/secrets/public-key",
		"/orgs/o/actions/variables",
		"/repos/o/r/environments/prod/secrets",
		"/repos/o/r/dependabot/secrets",
		"/repos/o/r/codespaces/secrets",
		"/user/keys",
		"/user/gpg_keys/1",
		"/user/ssh_signing_keys",
		"/user/emails",
		"/orgs/o/members",
		"/gists",
		"/gists/abc",
		"/authorizations",
		"/installation/repositories",
	} {
		if got := defaultDecision("http.request", "GET https://api.github.com"+p); got != "escalate" {
			t.Errorf("GET %s: %s, want escalate", p, got)
		}
	}
	for _, p := range []string{"/repos/o/r", "/repos/o/r/pulls", "/repos/o/r/contents/README.md"} {
		if got := defaultDecision("http.request", "GET https://api.github.com"+p); got != "allow" {
			t.Errorf("GET %s: %s, want allow", p, got)
		}
	}
}

// CR-06: Slack API calls by GET pause and are not described as reads.
func TestSlackAPIGetIsACall(t *testing.T) {
	if got := defaultDecision("http.request", "GET https://slack.com/api/chat.postMessage"); got != "escalate" {
		t.Fatalf("GET slack.com/api: %s", got)
	}
	d := describe("GET https://slack.com:443/api/chat.postMessage?channel=C1")
	if strings.HasPrefix(d, "read ") || !strings.Contains(d, "chat.postMessage") {
		t.Fatalf("describe = %q", d)
	}
	if d := describe("GET https://acme.slack.com/api/conversations.history"); strings.HasPrefix(d, "read ") {
		t.Fatalf("workspace host: describe = %q", d)
	}
	if d := describe("GET https://slack.com/intl/en-gb/"); !strings.HasPrefix(d, "read ") {
		t.Fatalf("a Slack web page is a read: %q", d)
	}
}

// CR-06: the default Slack binding is the API host, not every workspace.
func TestDefaultSlackBindingIsAPIHost(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range cfg.Credentials {
		if strings.Contains(b.Host, "*") && strings.Contains(b.Host, "slack") {
			t.Errorf("wildcard Slack binding: %q", b.Host)
		}
		if b.Host == "slack.com" {
			found = true
		}
	}
	if !found {
		t.Error("no slack.com binding")
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustableHost(t *testing.T) {
	for res, want := range map[string]string{
		"GET https://docs.example.com/page":       "docs.example.com",
		"HEAD https://API.Example.COM:443/x":      "api.example.com",
		"GET https://example.com./x":              "example.com",
		"GET https://sub.domain.example.co.uk/a":  "sub.domain.example.co.uk",
	} {
		if got, ok := trustableHost(res); !ok || got != want {
			t.Errorf("trustableHost(%q) = %q,%v want %q", res, got, ok, want)
		}
	}
	// Anything that is not a plain read from a named https host is refused:
	// "trust" must never be able to open writes, wildcards or raw addresses.
	for _, res := range []string{
		"POST https://example.com/x",
		"DELETE https://example.com/x",
		"PUT https://example.com/x",
		"GET http://example.com/x",
		"GET https://10.0.0.5/x",
		"GET https://8.8.8.8/x",
		"GET https://localhost/x",
		"GET https://*.example.com/x",
		"GET https://user:pw@example.com/x",
		"GET https://exa mple.com/x",
		"GET",
		"",
	} {
		if h, ok := trustableHost(res); ok {
			t.Errorf("trustableHost(%q) accepted host %q; it must not", res, h)
		}
	}
}

func TestTrustReadHost_AddsReadOnlyRulesOnce(t *testing.T) {
	dir := t.TempDir()
	orig := `{"version":"v1","rules":[{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	added, err := trustReadHost(dir, "docs.example.com")
	if err != nil || !added {
		t.Fatalf("first call: added=%v err=%v", added, err)
	}
	if added, _ := trustReadHost(dir, "docs.example.com"); added {
		t.Fatal("trusting the same host twice must not add duplicate rules")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("policy.json no longer valid JSON: %v", err)
	}
	if len(doc.Rules) != 3 {
		t.Fatalf("want 3 rules (GET, HEAD, original), got %d: %s", len(doc.Rules), raw)
	}
	for _, r := range doc.Rules[:2] {
		res, _ := r["resource"].(string)
		if !strings.HasPrefix(res, "GET https://docs.example.com/") && !strings.HasPrefix(res, "HEAD https://docs.example.com/") {
			t.Errorf("unexpected rule %q: only GET/HEAD for the one host may be added", res)
		}
		if r["allow"] != true || r["deny"] == true || r["escalate"] == true {
			t.Errorf("rule must be a plain allow: %v", r)
		}
	}
	if doc.Rules[2]["resource"] != "POST *" {
		t.Error("the existing rules must be preserved after the new ones")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "policy.json")); fi != nil && filepath.Separator == '/' && fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", fi.Mode().Perm())
	}
	// no temp files left behind
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".policy-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestTrustReadHost_RefusesABrokenPolicyFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{not json"), 0o600)
	if _, err := trustReadHost(dir, "docs.example.com"); err == nil {
		t.Fatal("must not overwrite a policy file it cannot parse")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "policy.json")); string(b) != "{not json" {
		t.Fatal("the unparseable file was modified")
	}
}

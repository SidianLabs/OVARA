package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/receipts"
)

func TestPolicySuggest_FromReceipts(t *testing.T) {
	dir := t.TempDir()
	chainFile, pubFile := filepath.Join(dir, "receipts.jsonl"), filepath.Join(dir, "pub.hex")
	chain, err := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "r.key"), pubFile)
	if chain != nil {
		t.Cleanup(func() { _ = chain.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	open := "[profile observe] [open read] any public host"
	for _, e := range []receipts.Entry{
		{Method: "GET", URL: "https://docs.rs/tokio/latest", Decision: "allow", Status: 200, Rule: open, Agent: "a"},
		{Method: "GET", URL: "https://docs.rs/serde?x=1", Decision: "allow", Status: 200, Rule: open, Agent: "a"},
		{Method: "HEAD", URL: "https://Docs.RS/", Decision: "allow", Status: 200, Rule: open, Agent: "b"},
		{Method: "GET", URL: "https://pypi.org/simple/", Decision: "allow", Status: 200, Rule: "Reading from pypi.org is allowed", Agent: "a"},
		{Method: "GET", URL: "https://internal.example/x", Decision: "escalate", Status: 503, Agent: "a"},
		{Method: "POST", URL: "https://api.example.com/v1/items?dry=1", Decision: "deny", Status: 403, Rule: "[profile observe] no writes", Agent: "a"},
		{Method: "POST", URL: "https://api.example.com/v1/items", Decision: "deny", Status: 403, Rule: "[profile observe] no writes", Agent: "a"},
		{Method: "POST", URL: "https://pastebin.com/api", Decision: "deny", Status: 403, Rule: "Blocked: paste site commonly used to leak data", Agent: "a"},
		{Method: "GET", URL: "http://plain.example/", Decision: "allow", Status: 200, Rule: open, Agent: "a"},
		{Method: "GET", URL: "https://10.0.0.5/", Decision: "escalate", Status: 503, Agent: "a"},
		{Method: "DELETE", URL: "https://api.github.com/repos/acme/app", Decision: "escalate", Status: 503, Agent: "a"},
		{Method: "GET", URL: "https://crates.io:443/api/v1/crates/serde", Decision: "escalate", Status: 503, Agent: "a"},
		{Method: "POST", URL: "https://api.example.com:8443/v1/items", Decision: "escalate", Status: 503, Agent: "a"},
		{Method: "POST", URL: "https://api.anthropic.com/v1/messages", Decision: "allow", Status: 200, Rule: "The agent may call its model", Agent: "a"},
	} {
		if _, err := chain.Append(e, false); err != nil {
			t.Fatal(err)
		}
	}
	rules, summary, err := suggestRules(chainFile, pubFile, "", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rules {
		got[r["resource"].(string)] = r["description"].(string)
		if r["allow"] != true || r["action_type"] != "http.request" || r["environment"] != "*" {
			t.Errorf("not a complete allow rule: %v", r)
		}
	}
	for _, want := range []string{
		"GET https://docs.rs/*", "HEAD https://docs.rs/*",
		"GET https://internal.example/*", "HEAD https://internal.example/*",
		"POST https://api.example.com/v1/items", "DELETE https://api.github.com/repos/acme/app",
		"GET https://crates.io/*", "HEAD https://crates.io/*", // the default port is dropped
		"POST https://api.example.com:8443/v1/items", // another port is kept
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(got) != 9 {
		t.Errorf("%d rules, want 9: %v", len(got), got)
	}
	if d := got["GET https://docs.rs/*"]; !strings.Contains(d, "3 request(s)") || !strings.HasPrefix(d, "[suggested ") {
		t.Errorf("docs.rs: %q", d)
	}
	if d := got["POST https://api.example.com/v1/items"]; !strings.Contains(d, "2 time(s)") || !strings.Contains(d, "exactly this write") {
		t.Errorf("write: %q", d)
	}
	if !strings.Contains(summary, "3 host(s) to read, 3 write(s) to decide") || !strings.Contains(summary, "verifies") {
		t.Errorf("summary: %s", summary)
	}

	// one agent's requests only
	rules, _, err = suggestRules(chainFile, pubFile, "b", 0, time.Now())
	if err != nil || len(rules) != 2 || rules[0]["resource"] != "GET https://docs.rs/*" {
		t.Fatalf("agent b: %v %v", err, rules)
	}
	// nothing from the last second
	if rules, _, err = suggestRules(chainFile, pubFile, "", time.Nanosecond, time.Now().Add(time.Hour)); err != nil || len(rules) != 0 {
		t.Fatalf("since: %v %v", err, rules)
	}

	// a chain that does not verify suggests nothing
	b, _ := os.ReadFile(chainFile)
	if err := os.WriteFile(chainFile, []byte(strings.Replace(string(b), "docs.rs/serde", "docs.rs/serdf", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := suggestRules(chainFile, pubFile, "", 0, time.Now()); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered chain: %v", err)
	}
}

func TestPolicySuggest_EmptyChain(t *testing.T) {
	rules, summary, err := suggestRules(filepath.Join(t.TempDir(), "none.jsonl"), "", "", 0, time.Now())
	if err != nil || len(rules) != 0 || !strings.Contains(summary, "0 host(s) to read") {
		t.Fatalf("%v %v %s", err, rules, summary)
	}
}

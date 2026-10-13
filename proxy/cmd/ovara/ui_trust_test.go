package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The page warns, on the button and before acting, that trusting a host
// stops the questions about reads from it.
func TestUI_TrustButtonSaysWhatItDoes(t *testing.T) {
	_, h := newUI(t)
	page := call(h, "GET", "/", "127.0.0.1", "").Body.String()
	for _, want := range []string{"stop asking about reads from", "will no longer be asked about", "window.confirm", "until ovara run stops"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// A rule trusted from a prompt says where it came from and when, and lasts
// one run: dropRunTrust removes it and nothing else.
func TestTrustReadHost_SaysWhereAndWhenAndLastsOneRun(t *testing.T) {
	dir := t.TempDir()
	orig := `{"version":"v1","rules":[
		{"action_type":"http.request","environment":"*","resource":"GET https://keep.example.com/*","allow":true,"description":"Trusted for reads by hand"},
		{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustReadHost(dir, "docs.example.com"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy.json"))
	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	json.Unmarshal(raw, &doc)
	desc, _ := doc.Rules[0]["description"].(string)
	for _, want := range []string{"[this run only]", "approval prompt", time.Now().Format("2006-01-02"), "docs.example.com"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description %q lacks %q", desc, want)
		}
	}

	hosts, err := dropRunTrust(dir)
	if err != nil || strings.Join(hosts, ",") != "docs.example.com" {
		t.Fatalf("dropRunTrust = %v, %v", hosts, err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "policy.json"))
	doc.Rules = nil
	json.Unmarshal(raw, &doc)
	if len(doc.Rules) != 2 || doc.Rules[0]["resource"] != "GET https://keep.example.com/*" || doc.Rules[1]["resource"] != "POST *" {
		t.Fatalf("rules after the run: %s", raw)
	}
	if hosts, err := dropRunTrust(dir); err != nil || len(hosts) != 0 {
		t.Fatalf("second drop: %v %v", hosts, err)
	}
}

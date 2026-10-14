package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Remembering is offered per request, in words that say what it does: for
// a read, this run or the project; for a command, this run; never for a
// write. The page asks before acting, and a scope the request does not
// offer is refused before anything is approved.
func TestUI_RememberOptionsAndScopes(t *testing.T) {
	f, c := newFake(t,
		pendingApproval{ApprovalID: "r1", ActionType: "http.request", Resource: "GET https://docs.example.com/x", CreatedAt: time.Now()},
		pendingApproval{ApprovalID: "c1", ActionType: "shell", Resource: "shell:rm -rf /tmp/x", CreatedAt: time.Now()},
		pendingApproval{ApprovalID: "w1", ActionType: "http.request", Resource: "POST https://api.example.com/x", CreatedAt: time.Now()})
	c.dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(c.dir, "policy.json"), []byte(`{"version":"v2-init","precedence":"most-specific","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, chainFile, pubFile := writeChain(t)
	h := (&uiServer{admin: c, pageToken: "tok", receiptsFile: chainFile, pubFile: pubFile}).handler()

	if page := call(h, "GET", "/", "127.0.0.1", "").Body.String(); !strings.Contains(page, "window.confirm") || !strings.Contains(page, "until ovara run stops") {
		t.Fatal("the page does not ask before remembering")
	}
	var list []struct {
		ID       string          `json:"id"`
		Remember []rememberScope `json:"remember"`
	}
	if err := json.Unmarshal(call(h, "GET", "/api/pending", "127.0.0.1", "Bearer tok").Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byID := map[string][]rememberScope{}
	for _, it := range list {
		byID[it.ID] = it.Remember
	}
	if r := byID["r1"]; len(r) != 2 || r[0].Key != scopeReadsRun || r[1].Key != scopeReadsProject ||
		!strings.Contains(r[0].Label, "stop asking about reads from docs.example.com") || !strings.Contains(r[0].Confirm, "will no longer be asked about until ovara run stops") ||
		!strings.Contains(r[1].Label, "for this project") {
		t.Fatalf("read options: %+v", r)
	}
	if o := byID["c1"]; len(o) != 1 || o[0].Key != scopeCommandRun || !strings.Contains(o[0].Confirm, "rm -rf /tmp/x") {
		t.Fatalf("command options: %+v", o)
	}
	if w := byID["w1"]; len(w) != 0 {
		t.Fatalf("a write offers nothing: %+v", w)
	}
	if rec := call(h, "POST", "/api/approve/w1?trust=1", "127.0.0.1", "Bearer tok"); rec.Code != 400 || f.resolved["w1"] != "" {
		t.Fatalf("a write remembered: %d %v", rec.Code, f.resolved)
	}
	if rec := call(h, "POST", "/api/approve/c1?remember=reads-run", "127.0.0.1", "Bearer tok"); rec.Code != 400 || f.resolved["c1"] != "" {
		t.Fatalf("a command remembered as reads: %d", rec.Code)
	}
	if rec := call(h, "POST", "/api/approve/r1?remember=reads-project", "127.0.0.1", "Bearer tok"); rec.Code != 200 || f.resolved["r1"] != "approve" {
		t.Fatalf("remember for the project: %d %s", rec.Code, rec.Body.String())
	}
	_, rules, _ := readPolicyDoc(c.dir)
	if len(rules) != 2 {
		t.Fatalf("rules: %v", rules)
	}
	if desc, _ := rules[0].(map[string]any)["description"].(string); !strings.HasPrefix(desc, projectMarker) || !strings.Contains(desc, "(browser)") || !strings.Contains(desc, "approval r1") {
		t.Fatalf("description %q", desc)
	}
	if what, _ := dropRunTrust(c.dir); len(what) != 0 {
		t.Fatalf("a project rule was dropped with the run: %v", what)
	}
	if rec := call(h, "POST", "/api/approve/c1?remember=command-run", "127.0.0.1", "Bearer tok"); rec.Code != 200 {
		t.Fatalf("remember a command: %d %s", rec.Code, rec.Body.String())
	}
	if what, _ := dropRunTrust(c.dir); strings.Join(what, ",") != "command `rm -rf /tmp/x`" {
		t.Fatalf("dropped %v", what)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

func TestStatus_OneDeploymentAtAGlance(t *testing.T) {
	dir := t.TempDir()
	tok := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), []byte(`{"gateway_url":"http://127.0.0.1:1","listen_addr":"127.0.0.1:9443","agent_token":"`+tok+`","agents":{"reviewer":"`+strings.Repeat("b", 64)+`"},"receipts_file":"var/receipts.jsonl","pubkey_file":"var/receipt_pubkey.hex","receipt_key_file":"var/receipt.key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"policy_file":"policy.json","policy_baseline_file":"baseline.json","policy_baseline_pubkey":"ab"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{"precedence":"most-specific","rules":[{"action_type":"http.request","environment":"*","resource":"GET *","allow":true,"description":"[profile balanced] [open read] reads"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := receipts.LoadOrCreate(inDir(dir, cfg.ReceiptsFile), inDir(dir, cfg.ReceiptKeyFile), inDir(dir, cfg.PubKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []receipts.Entry{
		{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: decisionAllow, Status: 200, Agent: tokenLabel(tok)},
		{Method: "POST", URL: "https://pastebin.com:443/api", Decision: decisionDeny, Agent: tokenLabel(tok)},
		{Method: "POST", URL: "https://api.github.com:443/x", Decision: decisionEscalate, Agent: "reviewer"},
		{Method: "GET", URL: "https://x.example:443/", Decision: decisionAllow, Status: 200, Agent: "gone"},
	} {
		if _, err := c.Append(e, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// reviewer is stopped; the default agent had a run
	rv := &config.RevokedAgents{Stopped: map[string]time.Time{"reviewer": time.Now()}}
	if err := rv.Save(filepath.Join(dir, "var", "revoked_agents.json")); err != nil {
		t.Fatal(err)
	}
	attestAfterRun(dir, cfg, "", time.Now().Add(-time.Minute), 0, 0, true)

	rep, err := deploymentStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Profile != "balanced" || rep.Baseline != "signed" || rep.PolicyHash == "" || rep.Gateway.Running || !rep.Receipts.Valid || rep.Receipts.Total != 4 {
		t.Fatalf("report: %+v", rep)
	}
	if len(rep.Agents) != 3 || rep.Agents[0].Name != "default" || rep.Agents[1].Name != "reviewer" || rep.Agents[2].Name != "gone" {
		t.Fatalf("agents: %+v", rep.Agents)
	}
	d, r, g := rep.Agents[0], rep.Agents[1], rep.Agents[2]
	if d.State != stateActive || d.Requests != (statusCounts{Allowed: 1, Denied: 1}) || d.Last == nil || d.Last.Host != "pastebin.com:443" || d.LastRun == nil || d.LastRun.Outcome != "clean" || d.Pending != -1 {
		t.Fatalf("default: %+v %+v %+v", d, d.Last, d.LastRun)
	}
	if r.State != stateStopped || r.StoppedAt == nil || r.Requests.Paused != 1 || r.LastRun != nil {
		t.Fatalf("reviewer: %+v", r)
	}
	if g.State != stateUnknown || g.Requests.Allowed != 1 {
		t.Fatalf("gone: %+v", g)
	}
	var buf bytes.Buffer
	printStatus(&buf, rep)
	out := buf.String()
	for _, want := range []string{"profile balanced", "org baseline signed", "not running", "4 verified", "default        active", "STOPPED", "gone           unknown", "run clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	// the JSON form carries the same
	js := capture(t, func() error { return cmdStatus([]string{"-dir", dir, "-json"}) })
	var back statusReport
	if err := json.Unmarshal([]byte(js), &back); err != nil || len(back.Agents) != 3 || back.Agents[0].LastRun == nil {
		t.Fatalf("json: %v\n%s", err, js)
	}
}

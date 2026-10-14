package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// fleetDeployment makes a deployment with a token, a policy and a few
// receipts, like a status test's.
func fleetDeployment(t *testing.T, root, name, profile string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tok := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), []byte(`{"gateway_url":"http://127.0.0.1:1","listen_addr":"127.0.0.1:9443","agent_token":"`+tok+`","receipts_file":"var/receipts.jsonl","pubkey_file":"var/receipt_pubkey.hex","receipt_key_file":"var/receipt.key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{"precedence":"most-specific","rules":[{"action_type":"http.request","environment":"*","resource":"GET *","allow":true,"description":"[profile `+profile+`] [open read] reads"}]}`), 0o600); err != nil {
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
	if _, err := c.Append(receipts.Entry{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: decisionAllow, Status: 200, Agent: tokenLabel(tok)}, true); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFleet_EveryDeploymentOnOneLine(t *testing.T) {
	root := t.TempDir()
	a := fleetDeployment(t, root, "alpha", "balanced")
	b := fleetDeployment(t, root, "beta", "observe")
	if err := os.MkdirAll(filepath.Join(root, "not-a-deployment"), 0o700); err != nil {
		t.Fatal(err)
	}
	dirs, err := fleetDirs("", root)
	if err != nil || len(dirs) != 2 || dirs[0] != a || dirs[1] != b {
		t.Fatalf("fleetDirs: %v %v", dirs, err)
	}
	entries := fleetStatus(append(dirs, filepath.Join(root, "missing")))
	if len(entries) != 3 {
		t.Fatalf("entries: %+v", entries)
	}
	if entries[0].Profile != "balanced" || entries[1].Profile != "observe" || entries[0].Receipts != 1 || !entries[0].Valid || entries[0].Agents != 1 || entries[0].Gateway {
		t.Fatalf("entries: %+v", entries)
	}
	if entries[0].Last == nil || time.Since(*entries[0].Last) > time.Minute {
		t.Fatalf("last activity: %v", entries[0].Last)
	}
	if entries[2].Error == "" {
		t.Fatalf("a missing deployment must be reported, not skipped: %+v", entries[2])
	}
	var out bytes.Buffer
	printFleet(&out, entries)
	s := out.String()
	if !strings.Contains(s, "alpha") || !strings.Contains(s, "balanced") || !strings.Contains(s, "stopped") || !strings.Contains(s, "1 ok") || !strings.Contains(s, "ERROR:") {
		t.Fatalf("table:\n%s", s)
	}
	if _, err := fleetDirs("", ""); err == nil {
		t.Fatal("no deployments named must be an error")
	}
}

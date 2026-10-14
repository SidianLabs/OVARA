package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/sandbox"
)

func TestAttestCLI_VerifyListShow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), []byte(`{"gateway_url":"http://127.0.0.1:1","listen_addr":"127.0.0.1:9443","agent_token":"t","receipts_file":"var/receipts.jsonl","pubkey_file":"var/receipt_pubkey.hex","receipt_key_file":"var/receipt.key"}`), 0o600); err != nil {
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
		{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: decisionAllow, Status: 200, PolicyHash: "p"},
		{Method: "POST", URL: "https://pastebin.com:443/api", Decision: decisionDeny, PolicyHash: "p"},
	} {
		if _, err := c.Append(e, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// nothing yet
	if err := cmdAttest([]string{"verify", "-dir", dir}); err == nil || !strings.Contains(err.Error(), "no attestation") {
		t.Fatalf("before any run: %v", err)
	}
	started := time.Now().Add(-time.Minute)
	attestAfterRun(dir, cfg, "", started, 0, 0, true)
	names, _ := attestationFiles(dir)
	if len(names) != 1 || names[0] != started.UTC().Format("20060102-150405")+".intoto.json" {
		t.Fatalf("written: %v", names)
	}
	out := capture(t, func() error { return cmdAttest([]string{"verify", "-dir", dir}) })
	if !strings.Contains(out, "attestation verifies") || !strings.Contains(out, "2 request(s): 1 allowed, 0 paused, 1 denied; 2 host(s)") {
		t.Fatalf("verify:\n%s", out)
	}
	out = capture(t, func() error { return cmdAttest([]string{"list", "-dir", dir}) })
	if !strings.Contains(out, "run ") || !strings.Contains(out, "default") || !strings.Contains(out, "clean") {
		t.Fatalf("list:\n%s", out)
	}
	out = capture(t, func() error { return cmdAttest([]string{"show", "-dir", dir}) })
	if !strings.Contains(out, attest.PredicateType) {
		t.Fatalf("show:\n%s", out)
	}
	// the bundle form: the file, the chain and the key named outright
	file := filepath.Join(attest.Dir(dir), names[0])
	out = capture(t, func() error {
		return cmdAttest([]string{"verify", file, "-receipts", inDir(dir, cfg.ReceiptsFile), "-pubkey", inDir(dir, cfg.PubKeyFile)})
	})
	if !strings.Contains(out, "attestation verifies") {
		t.Fatalf("bundle form:\n%s", out)
	}
	// a different chain than the one attested
	other := filepath.Join(dir, "other.jsonl")
	c2, _ := receipts.LoadOrCreate(other, inDir(dir, cfg.ReceiptKeyFile), inDir(dir, cfg.PubKeyFile))
	_, _ = c2.Append(receipts.Entry{Method: "GET", URL: "https://x.example:443/", Decision: decisionAllow, PolicyHash: "p"}, true)
	_ = c2.Close()
	if err := cmdAttest([]string{"verify", file, "-receipts", other, "-pubkey", inDir(dir, cfg.PubKeyFile)}); err == nil {
		t.Fatal("verified against another chain")
	}
	// a run with nothing in it still gets one, and the box form carries the manifest
	o := defaultBoxOptions()
	o.dir, o.cmd = dir, []string{"true"}
	o.project = dir
	sum := &sandbox.Summary{Outcome: sandbox.OutcomeKept, CommitBack: "disabled"}
	rel, err := attestBoxRun(o, cfg, "20261014-060000", started, 2, "", sum)
	if err != nil || rel != "var/attestations/20261014-060000.intoto.json" {
		t.Fatalf("box attestation: %v %q", err, rel)
	}
	man, _ := o.manifest().Encode()
	mf := filepath.Join(dir, "m.json")
	_ = os.WriteFile(mf, man, 0o600)
	out = capture(t, func() error {
		return cmdAttest([]string{"verify", "-dir", dir, "-run", "20261014-060000", "-manifest", mf})
	})
	if !strings.Contains(out, "attestation verifies") || !strings.Contains(out, "0 request(s)") {
		t.Fatalf("box form:\n%s", out)
	}
}

// capture runs f with standard output captured; a non-nil error is part of the output.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := f()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if err != nil {
		buf.WriteString("ERROR: " + err.Error())
	}
	return buf.String()
}

// A run attested as it goes: interim statements as receipts arrive, a
// final one at the end, the sequence verified as one.
func TestRollingAttestation_CutsChainAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), []byte(`{"gateway_url":"http://127.0.0.1:1","listen_addr":"127.0.0.1:9443","agent_token":"t","receipts_file":"var/receipts.jsonl","pubkey_file":"var/receipt_pubkey.hex","receipt_key_file":"var/receipt.key","attest_every_minutes":10}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttestEveryMinutes != 10 {
		t.Fatalf("attest_every_minutes not read: %d", cfg.AttestEveryMinutes)
	}
	c, err := receipts.LoadOrCreate(inDir(dir, cfg.ReceiptsFile), inDir(dir, cfg.ReceiptKeyFile), inDir(dir, cfg.PubKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	add := func(n int) {
		for i := 0; i < n; i++ {
			if _, err := c.Append(receipts.Entry{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: decisionAllow, Status: 200, PolicyHash: "p"}, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	started := time.Now().Add(-time.Hour)
	roll := newRolling(dir, cfg, "worker", started, 0)
	var logged []string
	roll.logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	// Nothing happened yet: an interim cut writes nothing.
	if rel, err := roll.cut(true, 0, true); err != nil || rel != "" {
		t.Fatalf("empty interim cut: %q %v", rel, err)
	}
	add(2)
	rel1, err := roll.cut(true, 0, true)
	if err != nil || !strings.HasSuffix(rel1, ".001.intoto.json") {
		t.Fatalf("first cut: %q %v", rel1, err)
	}
	add(3)
	if rel2, err := roll.cut(true, 0, true); err != nil || !strings.HasSuffix(rel2, ".002.intoto.json") {
		t.Fatalf("second cut: %q %v", rel2, err)
	}
	add(1)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	roll.final(0, true)
	if len(logged) == 0 || !strings.Contains(logged[len(logged)-1], ".003.intoto.json") {
		t.Fatalf("final: %v", logged)
	}
	out := capture(t, func() error { return cmdAttest([]string{"verify", "-dir", dir}) })
	if !strings.Contains(out, "sequence of 3 statement(s) verifies: receipts 0 to 6") {
		t.Fatalf("verify:\n%s", out)
	}
	out = capture(t, func() error { return cmdAttest([]string{"list", "-dir", dir}) })
	if !strings.Contains(out, "#3") || !strings.Contains(out, "running") || !strings.Contains(out, "clean") {
		t.Fatalf("list:\n%s", out)
	}
	// A run that was never cut is attested once, as before.
	plain := newRolling(dir, cfg, "worker", started.Add(time.Minute), 6)
	plain.logf = func(string, ...any) {}
	rel, err := plain.cut(false, 0, true)
	if err != nil || strings.Contains(rel, ".00") {
		t.Fatalf("a single statement: %q %v", rel, err)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// writeChain records n receipts into a fresh deployment's chain, with the
// local anchors `ovara run` writes, and returns the chain path.
func writeAnchoredChain(t *testing.T, dir string, n int) string {
	t.Helper()
	cfg, err := config.Load(filepath.Join(dir, "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(dir, cfg.ReceiptsFile)
	chain, err := receipts.LoadOrCreate(chainPath, filepath.Join(dir, cfg.ReceiptKeyFile), filepath.Join(dir, cfg.PubKeyFile))
	if chain != nil {
		t.Cleanup(func() { _ = chain.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	chain.SetAnchoring(receipts.AnchorPathFor(chainPath), "", 1)
	for i := 0; i < n; i++ {
		if _, err := chain.Record("GET", "https://pypi.org/simple/x/", "allow", 200, ""); err != nil {
			t.Fatal(err)
		}
	}
	return chainPath
}

func truncateLines(t *testing.T, path string, keep int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if keep > len(lines) {
		keep = len(lines)
	}
	if err := os.WriteFile(path, bytes.Join(lines[:keep], nil), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A log cut short verifies link by link; the anchors written as it grew are
// what catch it. `ovara log` and `ovara doctor` must both say so.
func TestTruncatedLogIsDetected(t *testing.T) {
	for _, keep := range []int{0, 2} {
		dir := t.TempDir()
		if _, err := deploy(dir, "0", false); err != nil {
			t.Fatal(err)
		}
		chainPath := writeAnchoredChain(t, dir, 5)
		cfg, _ := config.Load(filepath.Join(dir, "proxy.json"))
		pubPath := filepath.Join(dir, cfg.PubKeyFile)

		var buf bytes.Buffer
		if err := printLog(&buf, chainPath, pubPath, 0); err != nil || !strings.Contains(buf.String(), "match their anchors") {
			t.Fatalf("intact anchored log should verify with anchors: %v\n%s", err, buf.String())
		}

		truncateLines(t, chainPath, keep)
		buf.Reset()
		if err := printLog(&buf, chainPath, pubPath, 0); err == nil || !strings.Contains(buf.String(), "TAMPERED") {
			t.Fatalf("keep=%d: truncated log was not reported as tampered:\n%s", keep, buf.String())
		}
		if st := statuses(auditDeployment(dir))["receipt chain"]; st != "FAIL" {
			t.Fatalf("keep=%d: doctor receipt chain = %s, want FAIL", keep, st)
		}
	}
}

// Cutting the log and then letting it grow again (a fork) must fail too.
func TestTruncateThenContinueIsDetected(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	chainPath := writeAnchoredChain(t, dir, 4)
	truncateLines(t, chainPath, 2)
	// The next run resumes from the cut tail and appends.
	anchors := receipts.AnchorPathFor(chainPath)
	before, _ := os.ReadFile(anchors)
	writeAnchoredChain(t, dir, 3)
	after, _ := os.ReadFile(anchors)
	if len(after) <= len(before) {
		t.Fatal("expected new anchors")
	}
	if st := statuses(auditDeployment(dir))["receipt chain"]; st != "FAIL" {
		t.Fatalf("forked log: doctor receipt chain = %s, want FAIL", st)
	}
}

func setJSON(t *testing.T, path string, kv map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		m[k] = v
	}
	out, _ := json.Marshal(m)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A URL alone anchors nothing; doctor must not say it does.
func TestDoctorAnchorNeedsMode(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	setJSON(t, filepath.Join(dir, "config.json"), map[string]any{"gateway_anchor_url": "https://anchor.example"})
	if st := statuses(auditDeployment(dir))["off-host anchor"]; st != "WARN" {
		t.Fatalf("url without mode: %s, want WARN", st)
	}
	setJSON(t, filepath.Join(dir, "config.json"), map[string]any{"gateway_anchor_mode": "strict"})
	if st := statuses(auditDeployment(dir))["off-host anchor"]; st != "FAIL" {
		t.Fatalf("strict without pin: %s, want FAIL", st)
	}
	setJSON(t, filepath.Join(dir, "config.json"), map[string]any{"gateway_anchor_pin": "abcd"})
	if st := statuses(auditDeployment(dir))["off-host anchor"]; st != "PASS" {
		t.Fatalf("strict with url and pin: %s, want PASS", st)
	}
}

// fail_open lives in proxy.json; doctor has to look there.
func TestDoctorSeesFailOpenInProxyJSON(t *testing.T) {
	for _, key := range []string{"fail_open", "unsafe_no_agent_auth"} {
		dir := t.TempDir()
		if _, err := deploy(dir, "0", false); err != nil {
			t.Fatal(err)
		}
		if st := statuses(auditDeployment(dir))["unsafe flags"]; st != "PASS" {
			t.Fatalf("fresh init unsafe flags = %s", st)
		}
		setJSON(t, filepath.Join(dir, "proxy.json"), map[string]any{key: true})
		if st := statuses(auditDeployment(dir))["unsafe flags"]; st != "FAIL" {
			t.Fatalf("%s=true in proxy.json: unsafe flags = %s, want FAIL", key, st)
		}
	}
}

// Agent-controlled text cannot drive the terminal.
func TestTermSafe(t *testing.T) {
	cases := map[string]string{
		"\x1b[2K\rread https://pypi.org": `\u{001B}[2K\u{000D}read https://pypi.org`,
		"a‮gnp.exe":                      `a\u{202E}gnp.exe`,
		"zero​width":                     `zero\u{200B}width`,
		"tag\U000E0041":                  `tag\u{E0041}`,
		"bell\x07 osc\u009d":             `bell\u{0007} osc\u{009D}`,
		"raw c1 byte\x9b":                `raw c1 byte\x9b`,
		"line1\r\nline2":                 "line1 ⏎ line2",
		"bad\xffbyte":                    `bad\xffbyte`,
		"plain ünïcode ok":               "plain ünïcode ok",
	}
	for in, want := range cases {
		if got := termSafe(in); got != want {
			t.Errorf("termSafe(%q) = %q, want %q", in, got, want)
		}
	}
	if got := termSafeLines("+ok\n+\x1b]0;x\x07"); got != "+ok\n+\\u{001B}]0;x\\u{0007}" {
		t.Errorf("termSafeLines = %q", got)
	}
	var buf bytes.Buffer
	printApproval(&buf, sanitizeApproval(pendingApproval{
		ApprovalID: "apr_1", Resource: "POST https://evil.example/x\x1b[1A\x1b[2K",
		Context: map[string]string{"body_preview": "\x1b[31mhi", "diff": "+a\n+\x1b[2Jb"},
	}))
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Fatalf("escape byte reached the terminal: %q", buf.String())
	}
}

// A run must not append to a log that was cut short since the last run.
func TestRunRefusesToResumeACutLog(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	chainPath := writeAnchoredChain(t, dir, 4)
	cfg, _ := config.Load(filepath.Join(dir, "proxy.json"))
	pub := filepath.Join(dir, cfg.PubKeyFile)
	anchors := receipts.AnchorPathFor(chainPath)
	if err := receipts.CheckBeforeResume(chainPath, anchors, pub); err != nil {
		t.Fatalf("intact log refused: %v", err)
	}
	truncateLines(t, chainPath, 2)
	if err := receipts.CheckBeforeResume(chainPath, anchors, pub); err == nil {
		t.Fatal("a cut log was accepted for appending")
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/receipts"
)

func writeChain(t *testing.T) (dir, chainFile, pubFile string) {
	t.Helper()
	dir = t.TempDir()
	chainFile = filepath.Join(dir, "receipts.jsonl")
	pubFile = filepath.Join(dir, "pub.hex")
	chain, err := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "r.key"), pubFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		m, u, d string
		s       int
		a       string
	}{
		{"GET", "https://pypi.org/simple/", "allow", 200, ""},
		{"POST", "https://github.com/acme/app.git/git-receive-pack refs/heads/main", "allow", 200, "apr_1"},
		{"POST", "https://pastebin.com/api", "deny", 403, ""},
		{"DELETE", "https://api.github.com/repos/acme/app", "escalate", 504, "apr_2"},
	} {
		if _, err := chain.Record(r.m, r.u, r.d, r.s, r.a); err != nil {
			t.Fatal(err)
		}
	}
	return dir, chainFile, pubFile
}

func TestPrintLog_PlainEnglishAndVerified(t *testing.T) {
	_, chainFile, pubFile := writeChain(t)
	var out bytes.Buffer
	if err := printLog(&out, chainFile, pubFile, 0); err != nil {
		t.Fatalf("printLog: %v\n%s", err, out.String())
	}
	s := out.String()
	for _, want := range []string{
		"allowed", "read https://pypi.org/simple/",
		"approved", "push to refs/heads/main on github.com/acme/app",
		"BLOCKED", "send data to https://pastebin.com/api",
		"timed out", "DELETE https://api.github.com/repos/acme/app",
		"1 allowed, 1 approved, 1 BLOCKED, 1 timed out",
		"integrity: ✓ all 4 receipts",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("log output missing %q:\n%s", want, s)
		}
	}
}

// Editing a past entry (say, to hide a blocked exfiltration attempt) must
// be caught.
func TestPrintLog_DetectsTampering(t *testing.T) {
	_, chainFile, pubFile := writeChain(t)
	data, _ := os.ReadFile(chainFile)
	tampered := strings.Replace(string(data), `"decision":"deny"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("test setup: nothing replaced")
	}
	if err := os.WriteFile(chainFile, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := printLog(&out, chainFile, pubFile, 0)
	if err == nil || !strings.Contains(out.String(), "TAMPERED") {
		t.Fatalf("tampering not detected: err=%v\n%s", err, out.String())
	}
}

func TestPrintLog_EmptyAndLastN(t *testing.T) {
	var out bytes.Buffer
	if err := printLog(&out, filepath.Join(t.TempDir(), "none.jsonl"), "x", 10); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no activity yet") {
		t.Fatalf("got %q", out.String())
	}
	_, chainFile, pubFile := writeChain(t)
	out.Reset()
	if err := printLog(&out, chainFile, pubFile, 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "showing the last 2 of 4") || strings.Contains(out.String(), "pypi.org") {
		t.Fatalf("last-N not applied:\n%s", out.String())
	}
}

// Approvals the agent has already given up on are not offered: approving
// them would do nothing and only confuse the person answering.
func TestWatchLoop_SkipsExpiredApprovals(t *testing.T) {
	f, c := newFake(t,
		pendingApproval{ApprovalID: "old", ActionType: "http.request", Resource: "POST https://a/x", CreatedAt: time.Now().Add(-10 * time.Minute)},
		pendingApproval{ApprovalID: "new", ActionType: "http.request", Resource: "POST https://a/y", CreatedAt: time.Now()})
	c.maxWait = time.Minute

	var out bytes.Buffer
	stop := make(chan struct{})
	time.AfterFunc(300*time.Millisecond, func() { close(stop) })
	if err := watchLoop(c, strings.NewReader("a\n"), &out, 10*time.Millisecond, stop); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "https://a/x") {
		t.Fatalf("expired approval was offered:\n%s", out.String())
	}
	if f.resolved["new"] != "approve" {
		t.Fatalf("fresh approval not handled: %v", f.resolved)
	}
}

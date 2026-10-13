package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

func deployWithChain(t *testing.T, n int) (dir, chainPath string) {
	t.Helper()
	dir = t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	return dir, writeAnchoredChain(t, dir, n)
}

// captureStdout runs fn with os.Stdout going to a buffer.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	err := fn()
	w.Close()
	os.Stdout = old
	return <-done, err
}

func TestLogExportJSONLIsTheSignedLines(t *testing.T) {
	dir, chainPath := deployWithChain(t, 3)
	out, err := captureStdout(t, func() error { return cmdLog([]string{"export", "-dir", dir, "-format", "jsonl"}) })
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(chainPath)
	if out != string(want) {
		t.Fatalf("jsonl export differs from the chain:\n%s\nvs\n%s", out, want)
	}
	// -since past everything exports nothing.
	out, err = captureStdout(t, func() error {
		return cmdLog([]string{"export", "-dir", dir, "-since", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})
	if err != nil || out != "" {
		t.Fatalf("since in the future: %q %v", out, err)
	}
}

func TestLogExportOCSF(t *testing.T) {
	dir, _ := deployWithChain(t, 2)
	out, err := captureStdout(t, func() error { return cmdLog([]string{"export", "-dir", dir, "-format", "ocsf"}) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %d", len(lines))
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["class_uid"] != float64(4002) || ev["activity_id"] != float64(3) || ev["type_uid"] != float64(400203) || ev["action"] != "Allowed" {
		t.Fatalf("bad OCSF event: %v", ev)
	}
	req := ev["http_request"].(map[string]any)
	if req["http_method"] != "GET" || req["url"].(map[string]any)["hostname"] != "pypi.org" {
		t.Fatalf("bad http_request: %v", req)
	}
}

// An edited log is not exported as if it were sound.
func TestLogExportRefusesTamperedChain(t *testing.T) {
	dir, chainPath := deployWithChain(t, 3)
	data, _ := os.ReadFile(chainPath)
	_ = os.WriteFile(chainPath, bytes.Replace(data, []byte("pypi.org"), []byte("pypi.org.evil"), 1), 0o600)
	out, err := captureStdout(t, func() error { return cmdLog([]string{"export", "-dir", dir}) })
	if err == nil || out != "" {
		t.Fatalf("tampered chain exported: %q %v", out, err)
	}
}

func TestVerifyOnly(t *testing.T) {
	dir, chainPath := deployWithChain(t, 3)
	out, err := captureStdout(t, func() error { return cmdLog([]string{"-verify-only", "-dir", dir}) })
	if err != nil || !strings.Contains(out, "OK: 3 receipts") || !strings.Contains(out, "anchors") {
		t.Fatalf("%q %v", out, err)
	}
	truncateLines(t, chainPath, 2)
	if _, err := captureStdout(t, func() error { return cmdLog([]string{"-verify-only", "-dir", dir}) }); err == nil {
		t.Fatal("a cut log passed -verify-only")
	}
}

// The incident bundle holds what is needed to check the chain offline, and
// the check passes on the bundle alone, for a cut from -since too.
func TestIncidentBundleVerifiesOffline(t *testing.T) {
	dir, chainPath := deployWithChain(t, 3)
	time.Sleep(5 * time.Millisecond)
	since := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	cfg, _ := config.Load(filepath.Join(dir, "proxy.json"))
	chain, err := receipts.LoadOrCreate(chainPath, filepath.Join(dir, cfg.ReceiptKeyFile), filepath.Join(dir, cfg.PubKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	chain.SetAnchoring(receipts.AnchorPathFor(chainPath), "", 1)
	_, _ = chain.Record("POST", "https://pastebin.com/api", "deny", 403, "")
	_, _ = chain.Record("GET", "https://pypi.org/simple/y/", "allow", 200, "")

	for _, args := range [][]string{nil, {"-since", since.Format(time.RFC3339Nano)}} {
		bundle := filepath.Join(t.TempDir(), "b.tar.gz")
		if _, err := captureStdout(t, func() error {
			return cmdIncident(append([]string{"bundle", "-dir", dir, "-out", bundle}, args...))
		}); err != nil {
			t.Fatal(err)
		}
		files := untar(t, bundle)
		for _, want := range []string{"README.txt", "receipts.jsonl", "segment.json", "anchors.jsonl", "receipt_pubkey.hex", "policy.json", "policy.sha256", "verify.txt"} {
			if _, ok := files[want]; !ok {
				t.Fatalf("bundle lacks %s", want)
			}
		}
		if !strings.Contains(string(files["README.txt"]), "ovara log -verify-only") || !strings.HasPrefix(string(files["policy.sha256"]), "sha256:") {
			t.Fatal("README or policy hash missing")
		}
		n := strings.Count(string(files["receipts.jsonl"]), "\n")
		if (args == nil && n != 5) || (args != nil && n != 2) {
			t.Fatalf("bundle %v holds %d receipts", args, n)
		}
		ex := t.TempDir()
		for name, b := range files {
			_ = os.WriteFile(filepath.Join(ex, name), b, 0o600)
		}
		verify := func() error {
			_, err := captureStdout(t, func() error {
				return cmdLog([]string{"-verify-only", "-receipts", filepath.Join(ex, "receipts.jsonl"),
					"-pubkey", filepath.Join(ex, "receipt_pubkey.hex"), "-segment", filepath.Join(ex, "segment.json")})
			})
			return err
		}
		if err := verify(); err != nil {
			t.Fatalf("bundle %v does not verify offline: %v", args, err)
		}
		// Dropping a receipt from the bundle is caught.
		truncateLines(t, filepath.Join(ex, "receipts.jsonl"), n-1)
		if err := verify(); err == nil {
			t.Fatalf("bundle %v with a receipt dropped verified", args)
		}
	}
}

func untar(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[strings.TrimPrefix(h.Name, "ovara-incident/")] = b
	}
}

// After a key rotation the whole log still verifies: old receipts under
// the old key's window, new ones under the new key.
func TestKeysRotateReceipt(t *testing.T) {
	dir, chainPath := deployWithChain(t, 2)
	time.Sleep(2 * time.Millisecond)
	if _, err := captureStdout(t, func() error { return cmdKeys([]string{"rotate-receipt", "-dir", dir}) }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	cfg, _ := config.Load(filepath.Join(dir, "proxy.json"))
	chain, err := receipts.LoadOrCreate(chainPath, filepath.Join(dir, cfg.ReceiptKeyFile), filepath.Join(dir, cfg.PubKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	chain.SetAnchoring(receipts.AnchorPathFor(chainPath), "", 1)
	_, _ = chain.Record("GET", "https://pypi.org/simple/z/", "allow", 200, "")
	var out bytes.Buffer
	if err := printLog(&out, chainPath, filepath.Join(dir, cfg.PubKeyFile), 0); err != nil || !strings.Contains(out.String(), "integrity: ✓ all 3") {
		t.Fatalf("log after rotation: %v\n%s", err, out.String())
	}
	if got := statuses(auditDeployment(dir))["receipt chain"]; got != "PASS" {
		t.Fatalf("doctor after rotation: %s", got)
	}
}

// G-17: init does not print the operator token; G-09: the files it writes
// are owner-only.
func TestInitKeepsTokenAndPolicyPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	out, err := captureStdout(t, func() error { return cmdInit([]string{dir}) })
	if err != nil {
		t.Fatal(err)
	}
	var gw struct {
		OperatorTokens []string `json:"operator_tokens"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	_ = json.Unmarshal(b, &gw)
	if len(gw.OperatorTokens) != 1 || strings.Contains(out, gw.OperatorTokens[0]) {
		t.Fatal("init printed the operator token")
	}
	if !strings.Contains(out, "config.json") {
		t.Fatalf("init must say where the token is: %s", out)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(dir, "policy.json"): 0o600,
		filepath.Join(dir, "var"):         0o700,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: %#o, want %#o", path, fi.Mode().Perm(), want)
		}
	}
}

// G-17: doctor warns on a readable policy and fails a readable issuer key.
func TestDoctorPolicyReadableAndIssuerKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	dir, _ := deployWithChain(t, 1)
	got := statuses(auditDeployment(dir))
	if got["policy.json permissions"] != "PASS" || got["activity record permissions"] != "PASS" {
		t.Fatalf("fresh deployment: %v", got)
	}
	_ = os.Chmod(filepath.Join(dir, "policy.json"), 0o644)
	_ = os.Chmod(filepath.Join(dir, "var", "issuer.key"), 0o644)
	_ = os.Chmod(filepath.Join(dir, "var", "receipts.jsonl"), 0o644)
	got = statuses(auditDeployment(dir))
	if got["policy.json permissions"] != "WARN" || got["secret file permissions"] != "FAIL" || got["activity record permissions"] != "WARN" {
		t.Fatalf("loose files: %v", got)
	}
}

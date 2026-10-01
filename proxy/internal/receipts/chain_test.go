package receipts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newChain(t *testing.T) (*Chain, string, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "receipts.jsonl")
	keyFile := filepath.Join(dir, "receipts.key")
	pubFile := filepath.Join(dir, "receipts.pub")
	c, err := LoadOrCreate(chainFile, keyFile, pubFile)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	pubHex, err := os.ReadFile(pubFile)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad pubkey file: %v", err)
	}
	return c, chainFile, ed25519.PublicKey(pub)
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var out [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if l != "" {
			out = append(out, []byte(l))
		}
	}
	return out
}

func TestRecordAndVerify(t *testing.T) {
	c, chainFile, pub := newChain(t)
	r, err := c.Record("GET", "https://a.com/x", "allow", 200, "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if r.ReceiptID == "" || r.PrevHash != "" || !strings.HasPrefix(r.Signature, "sig_v1:") {
		t.Fatalf("bad receipt: %+v", r)
	}
	res := VerifyFile(chainFile, pub)
	if !res.Valid || res.Total != 1 {
		t.Fatalf("verify failed: %+v", res)
	}
}

func TestChainLinkage(t *testing.T) {
	c, chainFile, pub := newChain(t)
	var rs []*Receipt
	for i := 0; i < 3; i++ {
		r, err := c.Record("GET", "https://a.com/", "allow", 200, "")
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
		rs = append(rs, r)
	}
	if rs[0].PrevHash != "" {
		t.Fatal("first receipt prev_hash should be empty")
	}
	if rs[1].PrevHash != rs[0].hash() || rs[2].PrevHash != rs[1].hash() {
		t.Fatal("prev_hash linkage incorrect")
	}
	res := VerifyFile(chainFile, pub)
	if !res.Valid || res.Total != 3 {
		t.Fatalf("verify failed: %+v", res)
	}
}

func tamper(t *testing.T, path string, lineIdx int, fn func(*Receipt)) {
	t.Helper()
	lines := readLines(t, path)
	var r Receipt
	if err := json.Unmarshal(lines[lineIdx], &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fn(&r)
	lines[lineIdx], _ = json.Marshal(r)
	var b strings.Builder
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestTamperedURLFails(t *testing.T) {
	c, chainFile, pub := newChain(t)
	for i := 0; i < 3; i++ {
		c.Record("GET", "https://a.com/", "allow", 200, "")
	}
	tamper(t, chainFile, 1, func(r *Receipt) { r.URL = "https://evil.com/" })
	res := VerifyFile(chainFile, pub)
	if res.Valid {
		t.Fatal("expected verification failure after URL tamper")
	}
	if res.FailAt != 1 {
		t.Fatalf("expected failure at index 1, got %d (%s)", res.FailAt, res.Reason)
	}
}

func TestTamperedSignatureFails(t *testing.T) {
	c, chainFile, pub := newChain(t)
	c.Record("GET", "https://a.com/", "allow", 200, "")
	tamper(t, chainFile, 0, func(r *Receipt) {
		r.Signature = "sig_v1:" + strings.Repeat("00", ed25519.SignatureSize)
	})
	res := VerifyFile(chainFile, pub)
	if res.Valid || res.Reason != "signature invalid" {
		t.Fatalf("expected signature failure, got %+v", res)
	}
}

func TestEmptyAndMissingFiles(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(empty, nil, 0o644)
	pub := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	res := VerifyFile(empty, pub)
	if !res.Valid || res.Total != 0 {
		t.Fatalf("empty file should verify as valid empty chain: %+v", res)
	}
	res = VerifyFile(filepath.Join(dir, "nonexistent.jsonl"), pub)
	if res.Valid || res.Reason == "" {
		t.Fatalf("missing file should fail with reason: %+v", res)
	}
}

func TestRestartResumesChain(t *testing.T) {
	c, chainFile, pub := newChain(t)
	c.Record("GET", "https://a.com/1", "allow", 200, "")
	// simulate restart: new Chain over same files
	dir := filepath.Dir(chainFile)
	c2, err := LoadOrCreate(chainFile, filepath.Join(dir, "receipts.key"), filepath.Join(dir, "receipts.pub"))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	r2, err := c2.Record("GET", "https://a.com/2", "deny", 0, "")
	if err != nil {
		t.Fatalf("record after restart: %v", err)
	}
	if r2.PrevHash == "" {
		t.Fatal("restarted chain lost prev_hash head")
	}
	res := VerifyFile(chainFile, pub)
	if !res.Valid || res.Total != 2 {
		t.Fatalf("post-restart verify failed: %+v", res)
	}
}

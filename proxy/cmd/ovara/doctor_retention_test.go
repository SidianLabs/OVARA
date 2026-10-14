package main

import (
	"os"
	"path/filepath"
	"testing"

	"ovara.proxy/internal/config"
)

func TestDoctor_Retention(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ReceiptsFile: "var/receipts.jsonl"}
	if auditRetention(dir, cfg) != nil {
		t.Fatal("no chain, something said")
	}
	if err := os.MkdirAll(filepath.Join(dir, "var", "attestations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "var", "receipts.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "var", "attestations", "r.intoto.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := auditRetention(dir, cfg)
	if len(out) != 1 || out[0].status != checkPass || out[0].detail != "receipt chain 3 B, 1 attestation(s)" {
		t.Fatalf("small: %+v", out)
	}
	f, err := os.OpenFile(filepath.Join(dir, "var", "receipts.jsonl"), os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(retentionWarnBytes); err != nil { // a sparse file: the size is what counts
		t.Fatal(err)
	}
	f.Close()
	out = auditRetention(dir, cfg)
	if len(out) != 1 || out[0].status != checkWarn || out[0].detail[:len("receipt chain 256.0 MiB")] != "receipt chain 256.0 MiB" {
		t.Fatalf("large: %+v", out)
	}
	if humanBytes(1536) != "1.5 KiB" || humanBytes(3<<30) != "3.0 GiB" || humanBytes(12) != "12 B" {
		t.Fatal("humanBytes")
	}
}

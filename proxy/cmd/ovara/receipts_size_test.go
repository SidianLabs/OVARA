package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// Many receipts: the chain rotates into compressed segments, still
// verifies end to end, doctor reports the size and warns over the limit,
// and the activity view reads across segments.
func TestReceipts_100kRotateCompressWarn(t *testing.T) {
	// 5k by default (still several segments); OVARA_LONG_TESTS=1 writes the
	// full 100k (the CI e2e job does, without -race)
	n := 5000
	segment := int64(256 << 10)
	if os.Getenv("OVARA_LONG_TESTS") == "1" {
		n, segment = 100000, 1<<20
	}
	dir := t.TempDir()
	cfg := &config.Config{
		ReceiptsFile: "var/receipts.jsonl", PubKeyFile: "var/receipt_pubkey.hex",
		ReceiptsSegmentBytes: segment, ReceiptsWarnBytes: segment,
	}
	chainPath := filepath.Join(dir, cfg.ReceiptsFile)
	chain, err := receipts.LoadOrCreate(chainPath, filepath.Join(dir, "var/receipt.key"), filepath.Join(dir, cfg.PubKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	chain.SetRotation(cfg.ReceiptsSegmentBytes)
	for i := 0; i < n; i++ {
		if _, err := chain.Record("GET", "https://registry.npmjs.org/some-package/-/some-package-1.2.3.tgz", "allow", 200, ""); err != nil {
			t.Fatal(err)
		}
	}
	segs := receipts.Segments(chainPath)
	if len(segs) < 3 {
		t.Fatalf("expected rotation into several segments, got %d", len(segs))
	}
	total, _ := receipts.Size(chainPath)
	var raw int64
	_ = receipts.ForEachLine(chainPath, func(l []byte) error { raw += int64(len(l)) + 1; return nil })
	// signatures and hashes are random and compress poorly; the rest well:
	// at least half of the space must be saved
	if total*2 > raw {
		t.Fatalf("not compacted: %d bytes on disk for %d raw", total, raw)
	}
	t.Logf("%d receipts: %d bytes raw, %d on disk (%d segments)", n, raw, total, len(segs))
	checks := auditReceipts(dir, cfg)
	var chainCheck, sizeCheck check
	for _, c := range checks {
		switch c.name {
		case "receipt chain":
			chainCheck = c
		case "receipt size":
			sizeCheck = c
		}
	}
	if chainCheck.status != "PASS" || !strings.Contains(chainCheck.detail, fmt.Sprintf("%d receipts verified", n)) {
		t.Fatalf("chain: %+v", chainCheck)
	}
	if sizeCheck.status != "WARN" || !strings.Contains(sizeCheck.detail, "compressed segment") {
		t.Fatalf("size: %+v", sizeCheck)
	}
	act, err := loadActivity(chainPath, filepath.Join(dir, cfg.PubKeyFile), 20)
	if err != nil || act.Total != n || len(act.Entries) != 20 || !act.Valid {
		t.Fatalf("activity across segments: total=%d entries=%d valid=%v err=%v", act.Total, len(act.Entries), act.Valid, err)
	}
	// under the limit: PASS
	cfg.ReceiptsWarnBytes = 1 << 40
	for _, c := range auditReceipts(dir, cfg) {
		if c.name == "receipt size" && c.status != "PASS" {
			t.Fatalf("under the limit: %+v", c)
		}
	}
}

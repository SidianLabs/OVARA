package main

import (
	"fmt"
	"os"
	"path/filepath"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// retentionWarnBytes is the receipt chain size past which the doctor says
// to export and bundle: the chain is append-only and verified whole, so
// it is read in full by every `ovara log`, export and attestation.
const retentionWarnBytes = 256 << 20

// auditRetention reports how much record the deployment holds and, past
// the mark, what to do about it (docs/operations.md, Retention).
func auditRetention(dir string, cfg *config.Config) []check {
	chain := inDir(dir, cfg.ReceiptsFile)
	size, segments := receipts.Size(chain)
	if _, err := os.Stat(chain); err != nil && segments == 0 {
		return nil // no chain yet: nothing to retain
	}
	n := 0
	if entries, err := os.ReadDir(attest.Dir(dir)); err == nil {
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				n++
			}
		}
	}
	what := "receipt chain " + humanBytes(size)
	if segments > 0 {
		what += fmt.Sprintf(" on disk (%d compressed segment(s) + the current file)", segments)
	}
	what += fmt.Sprintf(", %d attestation(s)", n)
	warn := cfg.ReceiptsWarnBytes
	if warn <= 0 {
		warn = retentionWarnBytes
	}
	switch {
	case size >= warn:
		return []check{{"retention", checkWarn, what + "; over receipts_warn_bytes: every verification reads the whole chain, segments included; export it (ovara log export -since), keep an incident bundle, and start a new deployment directory for new runs (docs/operations.md, Retention)"}}
	case cfg.ReceiptsSegmentBytes < 0:
		return []check{{"retention", checkPass, what + "; rotation is off (receipts_segment_bytes < 0), so the current file grows without limit"}}
	}
	return []check{{"retention", checkPass, what}}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

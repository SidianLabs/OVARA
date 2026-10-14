package main

import (
	"fmt"
	"os"
	"path/filepath"

	"ovara.proxy/internal/attest"
	"ovara.proxy/internal/config"
)

// retentionWarnBytes is the receipt chain size past which the doctor says
// to export and bundle: the chain is append-only and verified whole, so
// it is read in full by every `ovara log`, export and attestation.
const retentionWarnBytes = 256 << 20

// auditRetention reports how much record the deployment holds and, past
// the mark, what to do about it (docs/operations.md, Retention).
func auditRetention(dir string, cfg *config.Config) []check {
	st, err := os.Stat(inDir(dir, cfg.ReceiptsFile))
	if err != nil {
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
	what := fmt.Sprintf("receipt chain %s, %d attestation(s)", humanBytes(st.Size()), n)
	if st.Size() >= retentionWarnBytes {
		return []check{{"retention", checkWarn, what + ": every verification reads the whole chain; export it (ovara log export -since), keep an incident bundle, and start a new deployment directory for new runs (docs/operations.md, Retention)"}}
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

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A configured persistent store that cannot be opened must stop the
// gateway. It used to log a warning and carry on with an empty in-memory
// store, so a tampered, rolled-back or corrupt journal silently became
// "no approvals, no receipts" instead of an alarm.
func TestRunRefusesToStartWhenConfiguredStoreCannotOpen(t *testing.T) {
	for _, key := range []string{
		"receipts_file", "approvals_file", "continuations_file", "execution_file", "events_file", "capabilities_file",
	} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			// A directory where the journal file should be: cannot be opened as a file.
			bad := filepath.Join(dir, "not-a-file")
			if err := os.Mkdir(bad, 0o755); err != nil {
				t.Fatal(err)
			}
			cfg := map[string]any{
				"server_port":     "0",
				"listen_addr":     "127.0.0.1",
				"enrollment_file": filepath.Join(dir, "enrollment.json"),
				key:               bad,
			}
			raw, _ := json.Marshal(cfg)
			cfgPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}

			errc := make(chan error, 1)
			go func() { errc <- Run(cfgPath) }()
			select {
			case err := <-errc:
				if err == nil || !strings.Contains(err.Error(), "refusing to start") {
					t.Fatalf("want a fail-closed startup error, got %v", err)
				}
			case <-after(5):
				t.Fatalf("Run kept serving with an unopenable %s (silent in-memory fallback)", key)
			}
		})
	}
}

func after(seconds int) <-chan time.Time { return time.After(time.Duration(seconds) * time.Second) }

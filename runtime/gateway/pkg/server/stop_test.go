package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Stop ends a running gateway the way a signal does: Run returns nil, and
// a Stop with no gateway running is harmless.
func TestStopEndsARunningGateway(t *testing.T) {
	Stop() // nothing running: no-op
	dir := t.TempDir()
	cfg := map[string]any{
		"server_port":     "0",
		"listen_addr":     "127.0.0.1",
		"enrollment_file": filepath.Join(dir, "enrollment.json"),
	}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- Run(cfgPath) }()
	// Give Run time to come up; a Stop before the goroutine registers would
	// be a no-op, and that is what the second Stop below also covers.
	time.Sleep(1500 * time.Millisecond)
	Stop()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run returned %v after Stop, want nil", err)
		}
	case <-after(10):
		t.Fatal("Run did not return after Stop")
	}
	Stop() // again: nothing running, no-op
}

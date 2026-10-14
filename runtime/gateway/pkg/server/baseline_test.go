package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.runtime.gateway/pkg/baseline"
)

// A pinned key with no valid signature stops the gateway: the
// organisation's layer is never silently skipped.
func TestRunRefusesAnUnsignedBaselineWhenAKeyIsPinned(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(base, []byte(`{"version":"org","precedence":"most-specific","rules":[{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _, err := baseline.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"server_port": "0", "listen_addr": "127.0.0.1",
		"enrollment_file":        filepath.Join(dir, "enrollment.json"),
		"policy_baseline_file":   base,
		"policy_baseline_pubkey": pub,
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
		if err == nil || !strings.Contains(err.Error(), "policy baseline") {
			t.Fatalf("Run returned %v, want a policy baseline error", err)
		}
	case <-after(15):
		Stop()
		t.Fatal("Run did not refuse to start")
	}
}

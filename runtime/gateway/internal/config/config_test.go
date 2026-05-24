package config

import "testing"

func TestConfigPolicyRefresh(t *testing.T) {
	cfg := Default()
	if cfg.PolicyRefreshInterval != 0 {
		t.Errorf("expected default 0 (disabled), got %d", cfg.PolicyRefreshInterval)
	}

	cfg.PolicyRefreshInterval = 300 // 5 minutes
	if cfg.PolicyRefreshInterval != 300 {
		t.Errorf("expected 300, got %d", cfg.PolicyRefreshInterval)
	}
}

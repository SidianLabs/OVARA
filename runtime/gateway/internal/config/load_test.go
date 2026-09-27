package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A well-formed config file round-trips: declared fields land, and an
// unset gateway_id gets a generated one rather than staying empty
// (every journal/receipt stamps it — empty would poison stores).
func TestLoad_ValidConfigRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"server_port": "9090",
		"listen_addr": "127.0.0.1",
		"gateway_id": "gw_fixed",
		"auth_enabled": true,
		"operator_tokens": ["tok1"],
		"trusted_issuers": {"iss_a": "aa"},
		"journal_signing_required": true
	}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerPort != "9090" || cfg.ListenAddr != "127.0.0.1" ||
		cfg.GatewayID != "gw_fixed" || !cfg.AuthEnabled ||
		len(cfg.OperatorTokens) != 1 || cfg.TrustedIssuers["iss_a"] != "aa" ||
		!cfg.JournalSigningRequired {
		t.Fatalf("fields did not round-trip: %+v", cfg)
	}
}

func TestLoad_GeneratesGatewayIDWhenUnset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"server_port":"8080"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GatewayID == "" {
		t.Fatal("empty gateway_id survived load — stores would stamp nothing")
	}
}

func TestEnrollment_StatusHelpers(t *testing.T) {
	cases := []struct {
		status   string
		isLocal  bool
		enrolled bool
	}{
		{EnrollmentStatusLocal, true, false},
		{EnrollmentStatusEnrolled, false, true},
		{EnrollmentStatusPending, false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		e := &Enrollment{Status: tc.status}
		if e.IsLocal() != tc.isLocal || e.IsEnrolled() != tc.enrolled {
			t.Errorf("status %q: IsLocal=%v IsEnrolled=%v", tc.status, e.IsLocal(), e.IsEnrolled())
		}
	}
}

// Bind-address parsing edge forms: bracketed v6 loopback and
// host:port loopback are dev-legit; a named external host is not.
func TestValidateStartup_BindAddrEdgeForms(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		c := &Config{ListenAddr: addr}
		if err := c.ValidateStartup(); err != nil {
			t.Errorf("loopback form %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{"example.com", "example.com:8080", "[::]:8080"} {
		c := &Config{ListenAddr: addr}
		if err := c.ValidateStartup(); err == nil {
			t.Errorf("non-loopback form %q allowed without auth", addr)
		}
	}
}

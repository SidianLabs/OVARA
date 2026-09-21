package config

// SEC-0017 regression — authentication and bind posture must fail closed.
// The old behavior: missing config → Default() (0.0.0.0, auth disabled,
// privileged APIs open). Every path below was a live exposure vector.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingConfigFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("missing config must be a startup error, not a silent Default()")
	}
}

func TestLoad_MalformedConfigFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("malformed config must be a startup error")
	}
}

func TestValidateStartup_NoAuthNonLoopbackRejected(t *testing.T) {
	for _, addr := range []string{"", "0.0.0.0", "0.0.0.0:8080", "192.168.1.5", "10.0.0.2", "172.16.0.1", "::"} {
		c := &Config{ListenAddr: addr, AuthEnabled: false}
		if err := c.ValidateStartup(); err == nil {
			t.Errorf("no-auth on bind %q must be rejected", addr)
		}
	}
}

func TestValidateStartup_NoAuthLoopbackAllowed(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "localhost", "::1"} {
		c := &Config{ListenAddr: addr, AuthEnabled: false}
		if err := c.ValidateStartup(); err != nil {
			t.Errorf("no-auth loopback %q should be allowed, got %v", addr, err)
		}
	}
}

func TestValidateStartup_UnsafeFlagOptsIn(t *testing.T) {
	c := &Config{ListenAddr: "0.0.0.0", AuthEnabled: false, UnsafeNoAuth: true}
	if err := c.ValidateStartup(); err != nil {
		t.Fatalf("explicit unsafe_no_auth should opt in, got %v", err)
	}
}

func TestValidateStartup_AuthEnabledPasses(t *testing.T) {
	c := &Config{ListenAddr: "0.0.0.0", AuthEnabled: true, OperatorTokens: []string{"x"}}
	if err := c.ValidateStartup(); err != nil {
		t.Fatalf("authenticated non-loopback should pass, got %v", err)
	}
}

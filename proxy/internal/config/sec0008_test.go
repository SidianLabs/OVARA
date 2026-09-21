package config

// SEC-0008 regression — startup posture for the credentialed proxy.
// A proxy that injects real credentials must not listen unauthenticated
// on a routable interface.

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "proxy.json")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestLoad_AllInterfacesNoTokenRejected(t *testing.T) {
	for _, addr := range []string{
		":9443", "0.0.0.0:9443", "[::]:9443",
		// every spelling of the unspecified address (red-team D finding)
		"[::0]:9443", "[0::]:9443", "[0:0:0:0:0:0:0:0]:9443",
		"[::ffff:0.0.0.0]:9443", "[0:0:0:0:0:0:0.0.0.0]:9443",
		"0.0.0.0", "::", "[::]",
	} {
		p := writeCfg(t, `{"listen_addr":"`+addr+`","gateway_url":"http://x"}`)
		if _, err := Load(p); err == nil {
			t.Errorf("listen %q with no agent_token must refuse to start", addr)
		}
	}
}

func TestLoad_AllInterfacesWithUnsafeFlagAllowed(t *testing.T) {
	p := writeCfg(t, `{"listen_addr":":9443","gateway_url":"http://x","unsafe_no_agent_auth":true}`)
	if _, err := Load(p); err != nil {
		t.Fatalf("explicit unsafe opt-in should start, got %v", err)
	}
}

func TestLoad_AllInterfacesWithTokenAllowed(t *testing.T) {
	p := writeCfg(t, `{"listen_addr":":9443","gateway_url":"http://x","agent_token":"t"}`)
	if _, err := Load(p); err != nil {
		t.Fatalf("authenticated all-interfaces should start, got %v", err)
	}
}

func TestLoad_LoopbackNoTokenAllowed(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9443", "10.200.188.1:9443", "172.30.0.1:9443"} {
		p := writeCfg(t, `{"listen_addr":"`+addr+`","gateway_url":"http://x"}`)
		if _, err := Load(p); err != nil {
			t.Errorf("specific bind %q without token should start (local trust domain), got %v", addr, err)
		}
	}
}

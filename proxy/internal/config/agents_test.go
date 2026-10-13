package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateAgents(t *testing.T) {
	tok := strings.Repeat("a", 64)
	ok := map[string]string{"ci-bot": tok, "reviewer_2": strings.Repeat("b", 64)}
	if err := ValidateAgents(ok, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	bad := []map[string]string{
		{"Upper": tok},
		{"": tok},
		{"default": tok},
		{"pt_1234": tok},
		{"*": tok},
		{"x": "short"},
		{"x": tok, "y": tok},
		{strings.Repeat("n", 33): tok},
	}
	for _, m := range bad {
		if err := ValidateAgents(m, ""); err == nil {
			t.Errorf("%v accepted", m)
		}
	}
	if err := ValidateAgents(map[string]string{"x": tok}, tok); err == nil {
		t.Error("an agent sharing agent_token accepted")
	}
}

func TestLoadAcceptsAgentsAsClientAuth(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "proxy.json")
	write := func(v map[string]any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]any{"gateway_url": "http://x", "listen_addr": ":9443", "agents": map[string]string{"a": strings.Repeat("a", 64)}})
	c, err := Load(p)
	if err != nil {
		t.Fatalf("named agents on all interfaces: %v", err)
	}
	if c.RevokedAgentsFile != "var/revoked_agents.json" {
		t.Fatalf("revoked file default %q", c.RevokedAgentsFile)
	}
	write(map[string]any{"gateway_url": "http://x", "agents": map[string]string{"A": strings.Repeat("a", 64)}})
	if _, err := Load(p); err == nil {
		t.Fatal("invalid agent name accepted")
	}
}

// `ovara agent add|remove` change only the agents map and keep the file
// owner-only; the revoked list round-trips and is written owner-only.
func TestWriteAgentsKeepsOtherFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(p, []byte(`{"gateway_url":"http://x","agent_token":"`+strings.Repeat("l", 64)+`","escalate_timeout_sec":42}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := NewAgentToken()
	if err != nil || len(tok) != 64 {
		t.Fatalf("token %q %v", tok, err)
	}
	if err := WriteAgents(p, map[string]string{"ci": tok}); err != nil {
		t.Fatal(err)
	}
	agents, legacy, err := ReadAgents(p)
	if err != nil || agents["ci"] != tok || legacy != strings.Repeat("l", 64) {
		t.Fatalf("read back %v %q %v", agents, legacy, err)
	}
	c, err := Load(p)
	if err != nil || c.EscalateTimeoutSec != 42 {
		t.Fatalf("other fields: %+v %v", c, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("proxy.json mode %v", fi.Mode().Perm())
		}
	}
	rp := filepath.Join(dir, "var", "revoked_agents.json")
	rv, err := LoadRevoked(rp)
	if err != nil || len(rv.Stopped) != 0 {
		t.Fatalf("missing file: %+v %v", rv, err)
	}
	rv.Stopped["ci"] = time.Now().UTC()
	if err := rv.Save(rp); err != nil {
		t.Fatal(err)
	}
	back, err := LoadRevoked(rp)
	if err != nil || len(back.Stopped) != 1 {
		t.Fatalf("round trip %+v %v", back, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(rp); fi.Mode().Perm() != 0o600 {
			t.Fatalf("revoked file mode %v", fi.Mode().Perm())
		}
	}
	if err := os.WriteFile(rp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRevoked(rp); err == nil {
		t.Fatal("broken revoked file read as empty")
	}
}

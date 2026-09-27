// Trust-wiring validation (extracted from Run so the C2-B invariants
// are testable): approver custody is local XOR remote, the remote
// custody path always requires the operator-held pubkey pin, approver
// and lineage roots both refuse to boot off ephemeral trust, and
// journal_signing_required refuses unsigned startup.
package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/config"
)

func testPin(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub)
}

const (
	keyFile = "a.key"
	linFile = "l.jsonl"
)

func TestValidateTrustConfig(t *testing.T) {
	pin := testPin(t)
	remote := func(c *config.Config) {
		c.ApproverSignerURL = "https://signer.local"
		c.ApproverSignerToken = "tok"
		c.ApproverSignerKeyID = "k1"
		c.ApproverPubKey = pin
	}
	cases := []struct {
		name    string
		durable bool
		mut     func(*config.Config)
		wantErr string // "" = accepted; else substring
		wantPin bool
	}{
		{"bare config, unsigned allowed", false, func(c *config.Config) {}, "", false},
		{"journal_signing_required refuses unsigned", false,
			func(c *config.Config) { c.JournalSigningRequired = true }, "journal_signing_required", false},
		{"journal_signing_required ok when durable", true,
			func(c *config.Config) { c.JournalSigningRequired = true }, "", false},
		{"approver local+remote is never both", true,
			func(c *config.Config) {
				c.ApproverKeyFile = keyFile
				remote(c)
			}, "never both", false},
		{"remote approver requires pubkey pin", true,
			func(c *config.Config) {
				c.ApproverSignerURL = "https://s"
				c.ApproverSignerToken = "t"
				c.ApproverSignerKeyID = "k"
			}, "requires approver_pubkey", false},
		{"local approver requires key+pubkey pair", true,
			func(c *config.Config) { c.ApproverKeyFile = keyFile }, "set together", false},
		{"remote approver requires all three", true,
			func(c *config.Config) {
				c.ApproverSignerURL = "https://s"
				c.ApproverPubKey = pin
			}, "set together", false},
		{"approver root refuses ephemeral trust", false, remote,
			"not durable", false},
		{"pubkey without a custody mode", true,
			func(c *config.Config) { c.ApproverPubKey = pin }, "custody mode", false},
		{"bad pin hex rejected", true,
			func(c *config.Config) {
				c.ApproverKeyFile = keyFile
				c.ApproverPubKey = "not-hex"
			}, "hex ed25519 public key", false},
		{"remote approver returns decoded pin", true, remote, "", true},
		{"local approver valid", true,
			func(c *config.Config) {
				c.ApproverKeyFile = keyFile
				c.ApproverPubKey = pin
			}, "", true},
		{"lineage requires all three paths", true,
			func(c *config.Config) { c.LineageFile = linFile }, "set together", false},
		{"lineage refuses ephemeral trust", false,
			func(c *config.Config) {
				c.LineageFile = linFile
				c.LineageLedgerFile = "led.jsonl"
				c.LineageLedgerKeyFile = "led.key"
			}, "requires durable", false},
		{"lineage full+durable ok", true,
			func(c *config.Config) {
				c.LineageFile = linFile
				c.LineageLedgerFile = "led.jsonl"
				c.LineageLedgerKeyFile = "led.key"
			}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			tc.mut(cfg)
			pinOut, err := validateTrustConfig(cfg, tc.durable)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("accepted or wrong error: %v", err)
				}
			}
			if tc.wantPin && len(pinOut) != ed25519.PublicKeySize {
				t.Fatalf("expected decoded pin, got %d bytes", len(pinOut))
			}
			if !tc.wantPin && pinOut != nil {
				t.Fatal("unexpected pin")
			}
		})
	}
}

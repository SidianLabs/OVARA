package config

import (
	"encoding/json"
	"fmt"
	"os"

	"ovara.proxy/internal/creds"
)

type Config struct {
	ListenAddr   string `json:"listen_addr"`   // default :9443
	GatewayURL   string `json:"gateway_url"`   // ovara gateway base URL
	GatewayToken string `json:"gateway_token"` // bearer token if gateway auth_enabled
	Environment  string `json:"environment"`   // dev/staging/production; default dev

	CACertFile string `json:"ca_cert_file"` // persisted CA cert (distribute to agent trust store)
	CAKeyFile  string `json:"ca_key_file"`

	ReceiptKeyFile string `json:"receipt_key_file"` // ed25519 private key (hex) for receipt signing
	ReceiptsFile   string `json:"receipts_file"`    // JSONL append-only receipt chain
	PubKeyFile     string `json:"pubkey_file"`      // where to write the receipt verify pubkey

	FailOpen bool `json:"fail_open"` // DANGEROUS: allow when gateway unreachable

	EscalateTimeoutSec int `json:"escalate_timeout_sec"` // hold escalated requests this long; default 60
	EscalatePollSec    int `json:"escalate_poll_sec"`    // approval status poll interval; default 2

	Credentials []creds.Binding `json:"credentials"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":9443"
	}
	if c.Environment == "" {
		c.Environment = "dev"
	}
	if c.GatewayURL == "" {
		return nil, fmt.Errorf("gateway_url is required")
	}
	if c.CACertFile == "" {
		c.CACertFile = "var/ca.pem"
	}
	if c.CAKeyFile == "" {
		c.CAKeyFile = "var/ca.key"
	}
	if c.ReceiptsFile == "" {
		c.ReceiptsFile = "var/receipts.jsonl"
	}
	if c.PubKeyFile == "" {
		c.PubKeyFile = "var/receipt_pubkey.hex"
	}
	if c.EscalateTimeoutSec <= 0 {
		c.EscalateTimeoutSec = 60
	}
	if c.EscalatePollSec <= 0 {
		c.EscalatePollSec = 2
	}
	return &c, nil
}

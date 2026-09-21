package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"ovara.proxy/internal/creds"
)

type Config struct {
	ListenAddr   string `json:"listen_addr"`   // default :9443
	GatewayURL   string `json:"gateway_url"`   // ovara gateway base URL
	GatewayToken string `json:"gateway_token"` // bearer token if gateway auth_enabled
	Environment  string `json:"environment"`   // dev/staging/production; default dev

	// AgentToken authenticates proxy CLIENTS. When set, every request must
	// present it via Proxy-Authorization (Basic password or Bearer) — the
	// standard mechanism tools send automatically when the proxy URL
	// carries credentials (http://agent:TOKEN@host:9443). A credentialed
	// proxy with no client auth is an open credential dispenser.
	AgentToken string `json:"agent_token"`
	// UnsafeNoAgentAuth explicitly permits running an unauthenticated
	// credentialed proxy. Without it, a non-loopback listen_addr requires
	// agent_token.
	UnsafeNoAgentAuth bool `json:"unsafe_no_agent_auth"`

	CACertFile string `json:"ca_cert_file"` // persisted CA cert (distribute to agent trust store)
	CAKeyFile  string `json:"ca_key_file"`

	ReceiptKeyFile string `json:"receipt_key_file"` // ed25519 private key (hex) for receipt signing
	ReceiptsFile   string `json:"receipts_file"`    // JSONL append-only receipt chain
	PubKeyFile     string `json:"pubkey_file"`      // where to write the receipt verify pubkey

	FailOpen bool `json:"fail_open"` // DANGEROUS: allow when gateway unreachable

	// GitGate controls git push (git-receive-pack) ref extraction: when on,
	// target ref names are appended to the policy resource string so
	// ref-level rules (e.g. "no push to main") can be expressed and are
	// captured in receipts. Default ON in proxy.New; set false to disable.
	// (Pointer so an absent field keeps the proxy default.)
	GitGate *bool `json:"git_gate"`

	EscalateTimeoutSec int `json:"escalate_timeout_sec"` // hold escalated requests this long; default 60
	EscalatePollSec    int `json:"escalate_poll_sec"`    // approval status poll interval; default 2

	SensitiveHosts []string `json:"sensitive_hosts"` // host globs that always escalate (pivot-risk services)

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
	if err := c.validateClientAuth(); err != nil {
		return nil, err
	}
	return &c, nil
}

// validateClientAuth fails closed: a credentialed proxy on a non-loopback
// bind MUST authenticate its clients unless the operator explicitly opted
// in to an open proxy.
func (c *Config) validateClientAuth() error {
	if c.AgentToken != "" || c.UnsafeNoAgentAuth {
		return nil
	}
	host := c.ListenAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	// Empty host (":9443") or ANY spelling of the unspecified address —
	// ::, ::0, 0::, 0:0:0:0:0:0:0:0, ::ffff:0.0.0.0 — is all-interfaces.
	// A credentialed proxy there is an open credential dispenser.
	if host == "" {
		return fmt.Errorf("refusing to start: credentialed proxy listening on all interfaces with no agent_token — set agent_token, bind to a boundary/loopback address, or set unsafe_no_agent_auth=true")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("refusing to start: credentialed proxy listening on all interfaces (%s) with no agent_token — set agent_token, bind to a boundary/loopback address, or set unsafe_no_agent_auth=true", c.ListenAddr)
	}
	return nil // specific bind without token: the boundary NIC's trust domain
}

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
	// EscalateOnTimeout is what an unanswered hold is answered with:
	// "timeout" (default): 504; "retry": 503 with Retry-After and the
	// approval id, the approval stays open, and the same request sent
	// again runs once it is approved. With a short escalate_timeout_sec
	// this is the fail-fast setting: the agent is told at once.
	EscalateOnTimeout string `json:"escalate_on_timeout,omitempty"`

	SensitiveHosts []string `json:"sensitive_hosts"` // host globs that always escalate (pivot-risk services)

	// ModelGate checks the JSON body of requests to model-provider APIs and
	// refuses features that make the provider fetch a URL or connect to a
	// server on the agent's behalf (MCP connectors, web fetch/search tools,
	// images or documents given by URL). Default ON; ModelHosts overrides the
	// hosts it applies to (default api.anthropic.com, api.openai.com).
	ModelGate  *bool    `json:"model_gate"`
	ModelHosts []string `json:"model_hosts"`
	// ModelGateAsk turns a model-gate refusal into a question for a person
	// (action type model.server_feature) instead of a flat refusal. Default
	// ON; false refuses those requests outright.
	ModelGateAsk *bool `json:"model_gate_ask"`

	// Request bodies are read in full before policy or a person sees the
	// request, and exactly those bytes are forwarded. A body over its limit
	// is refused, never sent unseen. Defaults: 1 MiB for ordinary bodies,
	// 256 MiB for git pushes, 1 MiB for git fetch negotiations.
	MaxHeldBodyBytes   int64 `json:"max_held_body_bytes"`
	MaxPushBytes       int64 `json:"max_push_bytes"`
	MaxUploadPackBytes int64 `json:"max_upload_pack_bytes"`
	// MaxReadRequestBytes bounds what a GET/HEAD can carry out in its path,
	// query and extra headers together (default 2048).
	MaxReadRequestBytes int `json:"max_read_request_bytes"`

	// EgressBudget limits allowed traffic per destination host per minute.
	// Past it a person is asked (action type egress.budget); an approval
	// doubles that host's allowance for the rest of the run.
	EgressBudget *EgressBudget `json:"egress_budget"`
	// OpenReads caps, per agent and run, the distinct hosts read under a
	// rule that allows reads from any host (the balanced and observe
	// profiles mark such rules "[open read]"). Past it a person is asked
	// once per further host (action type egress.open_hosts).
	OpenReads *OpenReads `json:"open_reads,omitempty"`

	// Agents are named proxy clients, each with its own token (name ->
	// token). The proxy accepts any of them, and agent_token too, records
	// the name in receipts and approvals, and keeps the taint rule and the
	// model budget per name. `ovara agent add|list|remove` edit this map;
	// a running proxy picks up changes within a second.
	Agents map[string]string `json:"agents,omitempty"`
	// RevokedAgentsFile lists agents stopped by `ovara kill` (default
	// var/revoked_agents.json). The proxy re-reads it within a second and
	// refuses every request from a stopped agent.
	RevokedAgentsFile string `json:"revoked_agents_file,omitempty"`
	// Taint turns on the rule that asks before writes made soon after the
	// agent read untrusted content. Default on.
	Taint *Taint `json:"taint,omitempty"`
	// ModelBudget caps model API use per agent per run. Past it a person is
	// asked (action type model.budget); an approval doubles the allowance.
	ModelBudget *ModelBudget `json:"model_budget,omitempty"`
	// MCPGate reads MCP traffic (JSON-RPC over HTTP) the policy lets
	// through: tool definitions are pinned per server and a new or changed
	// one is asked about (action type mcp.tools); every tool call is asked
	// about (mcp.tool_call). Default ON. MCPPinsFile is where the pins are
	// kept (default var/mcp_pins.json).
	MCPGate     *bool  `json:"mcp_gate"`
	MCPPinsFile string `json:"mcp_pins_file"`

	Credentials []creds.Binding `json:"credentials"`

	// ScopeRepo ("owner/repo"), set by `ovara run -scope-repo` (which
	// `ovara box` passes for the project it boxes), narrows the GitHub
	// credentials to that one repository for the run. Not read from the file.
	ScopeRepo string `json:"-"`
}

// EgressBudget is the per-host allowance for allowed traffic. Zero fields
// keep the defaults (600 requests and 8 MiB of request data per minute).
type EgressBudget struct {
	Off               bool  `json:"off"`
	RequestsPerMinute int   `json:"requests_per_minute"`
	BytesPerMinute    int64 `json:"bytes_per_minute"`
}

// OpenReads is the per-agent cap on distinct unlisted hosts read under an
// open-read rule. Zero keeps the default (50 hosts per agent per run).
type OpenReads struct {
	Off      bool `json:"off"`
	MaxHosts int  `json:"max_hosts"`
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
	if c.RevokedAgentsFile == "" {
		c.RevokedAgentsFile = "var/revoked_agents.json"
	}
	if err := ValidateAgents(c.Agents, c.AgentToken); err != nil {
		return nil, err
	}
	if c.MCPPinsFile == "" {
		c.MCPPinsFile = "var/mcp_pins.json"
	}
	if c.EscalateTimeoutSec <= 0 {
		c.EscalateTimeoutSec = 60
	}
	if c.EscalatePollSec <= 0 {
		c.EscalatePollSec = 2
	}
	switch c.EscalateOnTimeout {
	case "":
		c.EscalateOnTimeout = "timeout"
	case "timeout", "retry":
	default:
		return nil, fmt.Errorf("escalate_on_timeout %q: use \"timeout\" or \"retry\"", c.EscalateOnTimeout)
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
	if c.AgentToken != "" || len(c.Agents) > 0 || c.UnsafeNoAgentAuth {
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

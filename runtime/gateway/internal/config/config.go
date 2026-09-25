package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerPort string `json:"server_port"`
	// ListenAddr overrides the bind address (default "0.0.0.0:<port>" for
	// backward compat). Set "127.0.0.1" when the only legitimate clients are
	// on-box — e.g. the executor proxy — so a bounded agent can never reach
	// the approval API and approve its own escalations.
	ListenAddr    string `json:"listen_addr"`
	PolicyVersion string `json:"policy_version"`
	PolicyFile    string `json:"policy_file"`
	// PolicyDir restricts all caller-supplied file paths on the policy
	// endpoints (file_path, candidate_file, ?file=) to this directory.
	// When empty, the directory containing PolicyFile is used; when neither
	// is set, file-based policy inputs are rejected.
	PolicyDir                    string   `json:"policy_dir"`
	LogLevel                     string   `json:"log_level"`
	FailClosed                   bool     `json:"fail_closed"`
	DecisionLogFile              string   `json:"decision_log_file"`
	GatewayID                    string   `json:"gateway_id"`
	GatewayName                  string   `json:"gateway_name"`
	GatewayVersion               string   `json:"gateway_version"`
	PolicyRefreshInterval        int      `json:"policy_refresh_interval"`
	ReceiptsFile                 string   `json:"receipts_file"`
	ReceiptsMaxSize              int      `json:"receipts_max_size"`
	ReceiptsMaxAgeMinutes        int      `json:"receipts_max_age_minutes"`
	ApprovalsFile                string   `json:"approvals_file"`
	EventsFile                   string   `json:"events_file"`
	EventsMaxSize                int      `json:"events_max_size"`
	ReceiptLogEnabled            bool     `json:"receipt_log_enabled"`
	DecisionCacheMaxSize         int      `json:"decision_cache_max_size"`
	DecisionCacheTTLMin          int      `json:"decision_cache_ttl_minutes"`
	EnrollmentFile               string   `json:"enrollment_file"`
	HeartbeatIntervalSec         int      `json:"heartbeat_interval_secs"`
	ContinuationsFile            string   `json:"continuations_file"`
	ContinuationsMaxSize         int      `json:"continuations_max_size"`
	ContinuationSweepIntervalSec int      `json:"continuation_sweep_interval_secs"`
	ContinuationRetentionDays    int      `json:"continuation_retention_days"`
	ContinuationMaxRecords       int      `json:"continuation_max_records"`
	EventsRetentionDays          int      `json:"events_retention_days"`
	EventsMaxRecords             int      `json:"events_max_records"`
	ExecutionFile                string   `json:"execution_file"`
	ExecutionsMaxSize            int      `json:"executions_max_size"`
	ExecutionRetentionDays       int      `json:"execution_retention_days"`
	ExecutionMaxRecords          int      `json:"execution_max_records"`
	ExecutionSweepIntervalSec    int      `json:"execution_sweep_interval_secs"`
	ExecutionStdoutLimitBytes    int      `json:"execution_stdout_limit_bytes"`
	ExecutionStderrLimitBytes    int      `json:"execution_stderr_limit_bytes"`
	ExecutionWorkingDir          string   `json:"execution_working_dir"`
	ExecutionAllowedEnvVars      []string `json:"execution_allowed_env_vars"`
	// ReplayFile enables durable replay protection (P2.1): request and
	// delegation consume records persist to an append-only journal so a
	// consumed capability stays consumed across restart/crash. When
	// empty, replay state is process-local in-memory (RC1 semantics).
	// Multiple gateway processes on one host may share this file — the
	// journal coordinates them via flock (one trusted state domain).
	ReplayFile     string `json:"replay_file"`
	ReplayMaxBytes int64  `json:"replay_max_bytes"`
	// IdentityRegistryFile enables durable stable-identity + credential
	// lifecycle state (P2.2). When empty the registry is in-memory:
	// runtime revocation works but dies at restart (RC1 parity — RC1
	// had no revocation at all). Single gateway = single trust domain.
	IdentityRegistryFile string `json:"identity_registry_file"`
	// GatewayRegistryFile enables the durable domain gateway-key
	// registry (P2.3.1): gw_id → registered ed25519 public keys +
	// lifecycle. When empty the registry is in-memory (runtime-only
	// trust — same convention as identity_registry_file). Configured
	// but unopenable/corrupt fails startup: persistence failure never
	// becomes successful trust.
	GatewayRegistryFile string `json:"gateway_registry_file"`
	// GatewayKeyFile is the gateway's ed25519 private key (0600).
	// Empty → ephemeral key generated at boot (runtime-only).
	GatewayKeyFile string `json:"gateway_key_file"`
	// TOFU pins (both or neither): expected enrollment gw_id and its
	// expected public key (hex). A mismatch fails startup — pinned
	// pre-provisioning, not a warning.
	GatewayExpectedID     string `json:"gateway_expected_id"`
	GatewayExpectedPubKey string `json:"gateway_expected_pubkey"`
	// GatewayForceRekey makes startup rotate (not register): our key
	// becomes ACTIVE, prior active keys enter bounded ROTATING grace.
	// Idempotent — restart-safe when the key file is unchanged.
	GatewayForceRekey bool `json:"gateway_force_rekey"`
	// GatewayKeyGraceSeconds bounds rotation dual-validity (default
	// 60s, max 24h — the P2.3 bounded-grace design).
	GatewayKeyGraceSeconds int `json:"gateway_key_grace_seconds"`
	// GatewayRequireAdmission (P2.3.2): when true a NEW gateway
	// identity may only enter ACTIVE via an operator-authorized
	// enrollment grant (gwctl grant) or a matching TOFU pin —
	// self-generated identity alone is not admission. Unset keeps
	// the P2.3.1 compat behavior (first-binding auto-admit, dev
	// mode — explicitly NOT a domain admission guarantee).
	GatewayRequireAdmission bool `json:"gateway_require_admission"`
	// GatewayAnchorMode (P2.3.3): "off" (default) | "strict" |
	// "degraded". Strict: every refusal case is fatal — oracle
	// unreachable, unregistered domain, rollback, equivocation,
	// unanchored tail. Degraded: rollback/equivocation still refuse;
	// unavailable oracle and unanchored tail only log (documented
	// weaker — use only while standing up Tier-1).
	GatewayAnchorMode string `json:"gateway_anchor_mode"`
	// GatewayAnchorURL — unix:///socket (Tier 1) or https://addr
	// (Tier 2, mTLS). Required when anchoring is on.
	GatewayAnchorURL string `json:"gateway_anchor_url"`
	// GatewayAnchorPin — expected oracle identity: "uid:<n>" for
	// unix, "key:<hex-ed25519-pub>" for https. Provisioned at domain
	// setup; rotation is an operator act. Mismatch fails closed.
	GatewayAnchorPin string `json:"gateway_anchor_pin"`
	// GatewayAnchorCatchup — "manual" (default) | "auto". Auto pushes
	// an unanchored tail on boot; honored ONLY in degraded mode
	// (strict never auto-pushes — a forged tail must never crown
	// itself). Documented-weaker opt-in.
	GatewayAnchorCatchup string `json:"gateway_anchor_catchup"`
	// GatewayAnchorKeyFile — the checkpoint signing key (Ed25519,
	// 0600), the domain's registered signing principal. Dedicated by
	// design: decoupled from gateway identity keys so identity
	// rotation never churns anchor lineage (anchor-key rotation uses
	// gwctl anchor-addkey). Empty falls back to gateway_key_file.
	GatewayAnchorKeyFile string `json:"gateway_anchor_key_file"`
	// JournalSigningRequired (P2.4/C1): when true, startup REFUSES
	// unless gateway trust is fully durable (gateway_registry_file
	// AND gateway_key_file both set) — signed journals need a signing
	// key that survives restart, so unsigned-legacy operation is an
	// explicit opt-out, never a silent downgrade.
	JournalSigningRequired bool `json:"journal_signing_required"`
	// ApproverKeyFile / ApproverPubKey (C2-B A1): when set, the
	// approvals journal signs under a SEPARATE approver-root key —
	// possessing gateway.key alone can no longer mint claimable
	// continuations. ApproverPubKey is the operator-held pin: the
	// presented key must equal it, and registry approver-role records
	// fold only against it. Both must be set together; requires durable
	// gateway trust (gateway_registry_file).
	ApproverKeyFile string `json:"approver_key_file"`
	ApproverPubKey  string `json:"approver_pubkey"`
	// ApproverSignerURL/Token/KeyID (C2-B A2): instead of a local
	// approver key file, delegate envelope signing to a remote signing
	// service (signerd) holding the key outside the gateway trust
	// domain — the gateway can request signatures but can never
	// extract the root. Mutually exclusive with approver_key_file;
	// approver_pubkey (the verification pin) is still required.
	ApproverSignerURL       string   `json:"approver_signer_url"`
	ApproverSignerToken     string   `json:"approver_signer_token"`
	ApproverSignerKeyID     string   `json:"approver_signer_key_id"`
	// LineageFile / LineageLedgerFile / LineageLedgerKeyFile (cross-
	// domain action lineage, docs/ACTION_LINEAGE.md): emit a signed,
	// ledger-registered lineage bundle at each authority boundary —
	// decision, approval, execution. The ledger is a THIRD party: its
	// key is distinct from the gateway key (a stolen gateway.key cannot
	// mint inclusions). All three must be set together and require
	// durable gateway trust; unset = emission off (runtime-only mode).
	LineageFile          string `json:"lineage_file"`
	LineageLedgerFile    string `json:"lineage_ledger_file"`
	LineageLedgerKeyFile string `json:"lineage_ledger_key_file"`
	CapabilitiesFile        string   `json:"capabilities_file"`
	CapabilitiesMaxSize     int      `json:"capabilities_max_size"`
	CapabilitiesHistoryFile string   `json:"capabilities_history_file"`
	OperatorTokens          []string `json:"operator_tokens"`
	// AgentTokens are lower-privilege credentials (e.g. the executor
	// proxy's gateway_token). They may call decision/approval-read APIs
	// but NEVER operator routes: approve/deny/resume, continuations,
	// policy mutation, shield, capability revocation, admin, audit/execution
	// export. A general operator token is gateway-root — keep it scarce.
	AgentTokens []string `json:"agent_tokens"`
	AuthEnabled bool     `json:"auth_enabled"`
	// UnsafeNoAuth explicitly opts in to running WITHOUT authentication.
	// Without it, auth_enabled=false is only permitted on a loopback bind;
	// a non-loopback listener with no auth is an unauthenticated privileged
	// API and the gateway refuses to start.
	UnsafeNoAuth bool `json:"unsafe_no_auth"`
	// EnableHostExecutors registers executors that run commands on the
	// gateway host itself (shell, exec, git.*). Default false — the
	// externally exposed API can never reach arbitrary host execution.
	EnableHostExecutors bool `json:"enable_host_executors"`
	BulkMaxBatchCap     int  `json:"bulk_max_batch_cap"`
	BulkDefaultBatch    int  `json:"bulk_default_batch"`

	ReceiptSigningKey string `json:"receipt_signing_key"`

	// TrustedIssuers maps capability-lease issuer ID to hex-encoded
	// ed25519 public key. If empty, signed leases cannot be verified
	// and lease validation fails closed.
	TrustedIssuers map[string]string `json:"trusted_issuers"`

	// AllowUnsignedLeases is an explicit opt-in that permits
	// /v1/capabilities/track to accept leases without signature
	// verification when no trusted_issuers are configured. Default false:
	// with no issuers configured, track rejects unsigned leases so prod
	// cannot silently skip verification.
	AllowUnsignedLeases bool `json:"allow_unsigned_leases"`

	OTELEnabled    bool    `json:"otel_enabled"`
	OTELEndpoint   string  `json:"otel_endpoint"`
	OTELSampleRate float64 `json:"otel_sample_rate"`

	StuckExecutingSweepIntervalSec     int `json:"stuck_executing_sweep_interval_secs"`
	StuckExecutingRecoveryThresholdMin int `json:"stuck_executing_recovery_threshold_min"`

	GitHubToken  string `json:"github_token"`
	CIToken      string `json:"ci_token"`
	CIWebhookURL string `json:"ci_webhook_url"`

	SLAApprovalMaxAgeMin        int            `json:"sla_approval_max_age_min"`
	SLARetryableMaxAgeMin       int            `json:"sla_retryable_max_age_min"`
	SLAPendingApprovalMaxAgeMin int            `json:"sla_pending_approval_max_age_min"`
	SLAExecutingMaxAgeMin       int            `json:"sla_executing_max_age_min"`
	SLAThresholds               map[string]int `json:"sla_thresholds"`
}

type Enrollment struct {
	GatewayID       string    `json:"gateway_id"`
	GatewayName     string    `json:"gateway_name"`
	Version         string    `json:"version"`
	Status          string    `json:"status"`
	EnrolledAt      time.Time `json:"enrolled_at,omitempty"`
	LastSeenAt      time.Time `json:"last_seen_at,omitempty"`
	ControlPlaneURL string    `json:"control_plane_url,omitempty"`
}

const (
	EnrollmentStatusLocal    = "local"
	EnrollmentStatusEnrolled = "enrolled"
	EnrollmentStatusPending  = "pending"
)

func (e *Enrollment) IsLocal() bool {
	return e.Status == EnrollmentStatusLocal
}

func (e *Enrollment) IsEnrolled() bool {
	return e.Status == EnrollmentStatusEnrolled
}

func Default() *Config {
	return &Config{
		ServerPort:                   "8080",
		PolicyVersion:                "v1-local",
		LogLevel:                     "info",
		FailClosed:                   false,
		DecisionLogFile:              "var/log/decisions.jsonl",
		GatewayID:                    newGatewayID(),
		GatewayName:                  "local-gateway",
		GatewayVersion:               "0.8.0",
		PolicyRefreshInterval:        0,
		ReceiptsFile:                 "var/data/receipts.json",
		ReceiptsMaxSize:              10000,
		ReceiptsMaxAgeMinutes:        60,
		ApprovalsFile:                "var/data/approvals.json",
		EventsFile:                   "var/data/events.jsonl",
		EventsMaxSize:                50000,
		ReceiptLogEnabled:            true,
		DecisionCacheMaxSize:         10000,
		DecisionCacheTTLMin:          10,
		EnrollmentFile:               "var/data/enrollment.json",
		HeartbeatIntervalSec:         30,
		ContinuationsFile:            "var/data/continuations.jsonl",
		ContinuationsMaxSize:         10000,
		ContinuationSweepIntervalSec: 60,
		ContinuationRetentionDays:    7,
		ContinuationMaxRecords:       10000,
		EventsRetentionDays:          7,
		EventsMaxRecords:             50000,
		ExecutionFile:                "var/data/executions.jsonl",
		ExecutionsMaxSize:            10000,
		ExecutionRetentionDays:       7,
		ExecutionMaxRecords:          10000,
		ExecutionSweepIntervalSec:    300,
		ExecutionStdoutLimitBytes:    1024 * 1024, // 1 MB
		ExecutionStderrLimitBytes:    256 * 1024,  // 256 KB
		ExecutionAllowedEnvVars:      []string{},
		CapabilitiesFile:             "var/data/capabilities.json",
		CapabilitiesMaxSize:          10000,
		CapabilitiesHistoryFile:      "var/data/capabilities_history.jsonl",
		OperatorTokens:               []string{},
		AuthEnabled:                  false,
		BulkMaxBatchCap:              100,
		BulkDefaultBatch:             20,

		OTELEnabled:    false,
		OTELEndpoint:   "localhost:4317",
		OTELSampleRate: 1.0,

		StuckExecutingSweepIntervalSec:     0,
		StuckExecutingRecoveryThresholdMin: 30,

		SLAApprovalMaxAgeMin:        30,
		SLARetryableMaxAgeMin:       60,
		SLAPendingApprovalMaxAgeMin: 30,
		SLAExecutingMaxAgeMin:       5,
		SLAThresholds:               map[string]int{},
	}
}

func newGatewayID() string {
	return fmt.Sprintf("gw_%d", time.Now().UnixNano()%1000000)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// FAIL CLOSED: a missing/unreadable config must never silently
		// become the open default (0.0.0.0 + no auth + privileged APIs).
		return nil, fmt.Errorf("failed to read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.GatewayID == "" {
		cfg.GatewayID = newGatewayID()
	}
	return &cfg, nil
}

// ValidateStartup rejects insecure deployment combinations. Called by the
// server before binding.
func (c *Config) ValidateStartup() error {
	if c.AuthEnabled {
		return nil
	}
	if c.UnsafeNoAuth {
		return nil // explicit opt-in — operator owns the risk
	}
	addr := c.ListenAddr
	if addr == "" {
		return fmt.Errorf("refusing to start: auth_enabled=false on the default bind (all interfaces) — set listen_addr=127.0.0.1, enable auth, or set unsafe_no_auth=true to explicitly opt in")
	}
	host := addr
	if ip := net.ParseIP(addr); ip == nil {
		// Not a bare IP literal — try host:port or [v6] forms.
		if i := strings.LastIndex(addr, ":"); i >= 0 && !strings.HasPrefix(addr, "[") {
			if _, err := strconv.Atoi(addr[i+1:]); err == nil {
				host = addr[:i]
			}
		}
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil // loopback-only unauthenticated is a legitimate dev mode
	}
	return fmt.Errorf("refusing to start: auth_enabled=false on non-loopback bind %q — set unsafe_no_auth=true to explicitly opt in", addr)
}

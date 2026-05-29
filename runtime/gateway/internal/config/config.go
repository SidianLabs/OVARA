package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ServerPort            string   `json:"server_port"`
	PolicyVersion         string   `json:"policy_version"`
	PolicyFile            string   `json:"policy_file"`
	LogLevel              string   `json:"log_level"`
	FailClosed            bool     `json:"fail_closed"`
	DecisionLogFile       string   `json:"decision_log_file"`
	GatewayID             string   `json:"gateway_id"`
	GatewayName           string   `json:"gateway_name"`
	GatewayVersion        string   `json:"gateway_version"`
	PolicyRefreshInterval int      `json:"policy_refresh_interval"`
	ReceiptsFile          string   `json:"receipts_file"`
	ReceiptsMaxSize       int      `json:"receipts_max_size"`
	ReceiptsMaxAgeMinutes  int      `json:"receipts_max_age_minutes"`
	ApprovalsFile         string   `json:"approvals_file"`
	EventsFile            string   `json:"events_file"`
	EventsMaxSize         int      `json:"events_max_size"`
	ReceiptLogEnabled     bool     `json:"receipt_log_enabled"`
	DecisionCacheMaxSize  int      `json:"decision_cache_max_size"`
	DecisionCacheTTLMin   int      `json:"decision_cache_ttl_minutes"`
	EnrollmentFile        string   `json:"enrollment_file"`
	HeartbeatIntervalSec  int      `json:"heartbeat_interval_secs"`
	ContinuationsFile    string   `json:"continuations_file"`
	ContinuationsMaxSize  int      `json:"continuations_max_size"`
	ContinuationSweepIntervalSec int `json:"continuation_sweep_interval_secs"`
	ContinuationRetentionDays   int    `json:"continuation_retention_days"`
	ContinuationMaxRecords      int    `json:"continuation_max_records"`
	EventsRetentionDays         int    `json:"events_retention_days"`
	EventsMaxRecords            int    `json:"events_max_records"`
	ExecutionFile               string `json:"execution_file"`
	ExecutionsMaxSize           int    `json:"executions_max_size"`
	ExecutionRetentionDays      int    `json:"execution_retention_days"`
	ExecutionMaxRecords         int    `json:"execution_max_records"`
	ExecutionSweepIntervalSec   int    `json:"execution_sweep_interval_secs"`
	ExecutionStdoutLimitBytes   int    `json:"execution_stdout_limit_bytes"`
	ExecutionStderrLimitBytes   int    `json:"execution_stderr_limit_bytes"`
	ExecutionWorkingDir         string `json:"execution_working_dir"`
	ExecutionAllowedEnvVars     []string `json:"execution_allowed_env_vars"`
	CapabilitiesFile            string   `json:"capabilities_file"`
	CapabilitiesMaxSize         int      `json:"capabilities_max_size"`
	CapabilitiesHistoryFile      string   `json:"capabilities_history_file"`
	OperatorTokens              []string `json:"operator_tokens"`
	AuthEnabled                 bool     `json:"auth_enabled"`
}

type Enrollment struct {
	GatewayID      string    `json:"gateway_id"`
	GatewayName    string    `json:"gateway_name"`
	Version        string    `json:"version"`
	Status         string    `json:"status"`
	EnrolledAt     time.Time `json:"enrolled_at,omitempty"`
	LastSeenAt     time.Time `json:"last_seen_at,omitempty"`
	ControlPlaneURL string   `json:"control_plane_url,omitempty"`
}

const (
	EnrollmentStatusLocal    = "local"
	EnrollmentStatusEnrolled = "enrolled"
	EnrollmentStatusPending = "pending"
)

func (e *Enrollment) IsLocal() bool {
	return e.Status == EnrollmentStatusLocal
}

func (e *Enrollment) IsEnrolled() bool {
	return e.Status == EnrollmentStatusEnrolled
}

func Default() *Config {
	return &Config{
		ServerPort:            "8080",
		PolicyVersion:         "v1-local",
		LogLevel:              "info",
		FailClosed:            false,
		DecisionLogFile:       "var/log/decisions.jsonl",
		GatewayID:              newGatewayID(),
		GatewayName:           "local-gateway",
		GatewayVersion:        "0.8.0",
		PolicyRefreshInterval:  0,
		ReceiptsFile:           "var/data/receipts.json",
		ReceiptsMaxSize:        10000,
		ReceiptsMaxAgeMinutes:  60,
		ApprovalsFile:         "var/data/approvals.json",
		EventsFile:            "var/data/events.jsonl",
		EventsMaxSize:         50000,
		ReceiptLogEnabled:      true,
		DecisionCacheMaxSize:   10000,
		DecisionCacheTTLMin:    10,
		EnrollmentFile:         "var/data/enrollment.json",
		HeartbeatIntervalSec:    30,
		ContinuationsFile:      "var/data/continuations.jsonl",
		ContinuationsMaxSize:   10000,
		ContinuationSweepIntervalSec: 60,
		ContinuationRetentionDays:     7,
		ContinuationMaxRecords:       10000,
		EventsRetentionDays:           7,
		EventsMaxRecords:              50000,
		ExecutionFile:             "var/data/executions.jsonl",
		ExecutionsMaxSize:         10000,
		ExecutionRetentionDays:    7,
		ExecutionMaxRecords:       10000,
		ExecutionSweepIntervalSec: 300,
		ExecutionStdoutLimitBytes: 1024 * 1024,  // 1 MB
		ExecutionStderrLimitBytes: 256 * 1024,   // 256 KB
		ExecutionAllowedEnvVars:   []string{},
		CapabilitiesFile:           "var/data/capabilities.json",
		CapabilitiesMaxSize:        10000,
		CapabilitiesHistoryFile:     "var/data/capabilities_history.jsonl",
		OperatorTokens:            []string{},
		AuthEnabled:              false,
	}
}

func newGatewayID() string {
	return fmt.Sprintf("gw_%d", time.Now().UnixNano()%1000000)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), nil
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
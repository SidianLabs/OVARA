package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ServerPort            string `json:"server_port"`
	PolicyVersion         string `json:"policy_version"`
	PolicyFile            string `json:"policy_file"`
	LogLevel              string `json:"log_level"`
	FailClosed            bool   `json:"fail_closed"`
	DecisionLogFile       string `json:"decision_log_file"`
	GatewayID             string `json:"gateway_id"`
	GatewayName           string `json:"gateway_name"`
	GatewayVersion        string `json:"gateway_version"`
	PolicyRefreshInterval  int    `json:"policy_refresh_interval"`
	ReceiptsFile          string `json:"receipts_file"`
	ReceiptsMaxSize       int    `json:"receipts_max_size"`
	ReceiptsMaxAgeMinutes  int    `json:"receipts_max_age_minutes"`
	ApprovalsFile         string `json:"approvals_file"`
	EventsFile            string `json:"events_file"`
	EventsMaxSize         int    `json:"events_max_size"`
	ReceiptLogEnabled     bool   `json:"receipt_log_enabled"`
	DecisionCacheMaxSize  int    `json:"decision_cache_max_size"`
	DecisionCacheTTLMin   int    `json:"decision_cache_ttl_minutes"`
	EnrollmentFile        string `json:"enrollment_file"`
	HeartbeatIntervalSec  int    `json:"heartbeat_interval_secs"`
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
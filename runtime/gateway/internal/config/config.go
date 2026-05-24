package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ServerPort      string `json:"server_port"`
	PolicyVersion   string `json:"policy_version"`
	PolicyFile      string `json:"policy_file"`
	LogLevel        string `json:"log_level"`
	FailClosed      bool   `json:"fail_closed"`
	DecisionLogFile string `json:"decision_log_file"`
	GatewayID       string `json:"gateway_id"`
	GatewayName     string `json:"gateway_name"`
	GatewayVersion   string `json:"gateway_version"`
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
		ServerPort:      "8080",
		PolicyVersion:  "v1-local",
		LogLevel:        "info",
		FailClosed:      false,
		DecisionLogFile: "var/log/decisions.jsonl",
		GatewayID:       newGatewayID(),
		GatewayName:     "local-gateway",
		GatewayVersion:  "0.7.0",
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
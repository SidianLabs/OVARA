package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerPort     string `json:"server_port"`
	PolicyVersion  string `json:"policy_version"`
	PolicyFile     string `json:"policy_file"`
	LogLevel       string `json:"log_level"`
	FailClosed     bool   `json:"fail_closed"`
	DecisionLogFile string `json:"decision_log_file"`
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
	return &cfg, nil
}

func Default() *Config {
	return &Config{
		ServerPort:     "8080",
		PolicyVersion:  "v1-local",
		LogLevel:       "info",
		FailClosed:     false,
		DecisionLogFile: "var/log/decisions.jsonl",
	}
}
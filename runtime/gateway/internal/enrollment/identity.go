package enrollment

import (
	"time"
)

type EnrollmentState string

const (
	EnrollmentStateLocal    EnrollmentState = "local"
	EnrollmentStateEnrolled EnrollmentState = "enrolled"
	EnrollmentStatePending  EnrollmentState = "pending"
)

type GatewayIdentity struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	Environment   string         `json:"environment"`
	RegisteredAt  time.Time      `json:"registered_at"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
	EnrollmentState EnrollmentState `json:"enrollment_state"`
	Tags          map[string]string `json:"tags,omitempty"`
}

type EnrollmentStatus struct {
	GatewayID        string         `json:"gateway_id"`
	EnrollmentState  EnrollmentState `json:"enrollment_state"`
	Environment     string         `json:"environment"`
	RegisteredAt    time.Time      `json:"registered_at,omitempty"`
	LastSeenAt      time.Time      `json:"last_seen_at,omitempty"`
	IsHealthy       bool           `json:"is_healthy"`
	PolicyVersion   string         `json:"policy_version,omitempty"`
	PolicySource    string         `json:"policy_source,omitempty"`
}
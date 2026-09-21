package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSeverity_Constants(t *testing.T) {
	tests := []struct {
		s        Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
	}
	for _, tt := range tests {
		if string(tt.s) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.s))
		}
	}
}

func TestAlertType_Constants(t *testing.T) {
	tests := []struct {
		at       AlertType
		expected string
	}{
		{AlertTypeAnomaly, "anomaly"},
		{AlertTypeTrustDegradation, "trust_degradation"},
		{AlertTypeContainment, "containment"},
		{AlertTypePolicyViolation, "policy_violation"},
		{AlertTypeCapabilityAbuse, "capability_abuse"},
	}
	for _, tt := range tests {
		if string(tt.at) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.at))
		}
	}
}

func TestAlertState_Constants(t *testing.T) {
	tests := []struct {
		s        AlertState
		expected string
	}{
		{AlertStateNew, "new"},
		{AlertStateAcknowledged, "acknowledged"},
		{AlertStateResolved, "resolved"},
	}
	for _, tt := range tests {
		if string(tt.s) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.s))
		}
	}
}

func TestConditionType_Constants(t *testing.T) {
	tests := []struct {
		c        ConditionType
		expected string
	}{
		{ConditionTrustBelow, "trust_below"},
		{ConditionAnomalyCount, "anomaly_count"},
		{ConditionExcessiveEscalations, "excessive_escalations"},
		{ConditionCapabilityChain, "capability_chain"},
	}
	for _, tt := range tests {
		if string(tt.c) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.c))
		}
	}
}

func TestAlert_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resolved := now.Add(time.Hour)

	original := Alert{
		ID:             "alert-001",
		Severity:       SeverityHigh,
		Type:           AlertTypeAnomaly,
		AgentID:        "agt-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		Action:         "shell:rm -rf /",
		Resource:       "shell:rm -rf /",
		TrustScore:     0.3,
		Message:        "Suspicious activity",
		Timestamp:      now,
		State:          AlertStateNew,
		AcknowledgedBy: "admin@example.com",
		ResolvedAt:     &resolved,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Alert
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("expected ID %q, got %q", original.ID, decoded.ID)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("expected severity %q, got %q", original.Severity, decoded.Severity)
	}
	if decoded.TrustScore != original.TrustScore {
		t.Errorf("expected trust score %f, got %f", original.TrustScore, decoded.TrustScore)
	}
	if decoded.ResolvedAt == nil {
		t.Error("expected resolved_at to be set")
	}
}

func TestAlert_OmitEmpty(t *testing.T) {
	a := Alert{
		ID:    "alert-002",
		State: AlertStateNew,
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// AcknowledgedBy and ResolvedAt should be omitted
	str := string(data)
	if str != "" {
		if contains(str, "acknowledged_by") {
			t.Error("expected acknowledged_by to be omitted")
		}
		if contains(str, "resolved_at") {
			t.Error("expected resolved_at to be omitted")
		}
	}
}

func TestAlertRule_JSON(t *testing.T) {
	rule := AlertRule{
		ID:            "rule-001",
		Name:          "Trust below threshold",
		Condition:     ConditionTrustBelow,
		Threshold:     0.5,
		WindowSeconds: 300,
		Severity:      SeverityHigh,
		Enabled:       true,
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AlertRule
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Threshold != 0.5 {
		t.Errorf("expected threshold 0.5, got %f", decoded.Threshold)
	}
	if decoded.WindowSeconds != 300 {
		t.Errorf("expected window 300, got %d", decoded.WindowSeconds)
	}
	if !decoded.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestAlertFilter_DefaultValues(t *testing.T) {
	f := AlertFilter{}
	if f.Severity != "" {
		t.Error("default severity should be empty")
	}
	if f.Limit != 0 {
		t.Error("default limit should be 0")
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

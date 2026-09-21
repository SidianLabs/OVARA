package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApprovalState_Constants(t *testing.T) {
	tests := []struct {
		s        ApprovalState
		expected string
	}{
		{StatePending, "pending"},
		{StateApproved, "approved"},
		{StateDenied, "denied"},
		{StateExpired, "expired"},
	}
	for _, tt := range tests {
		if string(tt.s) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.s))
		}
	}
}

func TestApproval_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resolved := now.Add(time.Minute)

	original := Approval{
		ID:          "appr-001",
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell",
		Resource:    "shell:rm -rf /",
		AgentID:     "agt-001",
		RequestedBy: "agt-001",
		State:       StatePending,
		Reason:      "High risk action",
		ResolvedBy:  "admin@example.com",
		ExpiresAt:   now.Add(24 * time.Hour),
		CreatedAt:   now,
		ResolvedAt:  &resolved,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Approval
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("expected ID %q, got %q", original.ID, decoded.ID)
	}
	if decoded.State != original.State {
		t.Errorf("expected state %q, got %q", original.State, decoded.State)
	}
	if decoded.ResolvedAt == nil {
		t.Error("expected resolved_at to be set")
	}
}

func TestApproval_OmitEmpty(t *testing.T) {
	a := Approval{
		ID:        "appr-002",
		GatewayID: "gw-001",
		State:     StatePending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	str := string(data)

	if contains(str, "agent_id") {
		t.Error("expected agent_id to be omitted")
	}
	if contains(str, "reason") {
		t.Error("expected reason to be omitted")
	}
	if contains(str, "resolved_by") {
		t.Error("expected resolved_by to be omitted")
	}
	if contains(str, "resolved_at") {
		t.Error("expected resolved_at to be omitted")
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

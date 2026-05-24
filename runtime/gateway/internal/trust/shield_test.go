package trust

import (
	"testing"
	"time"
)

func TestNewShieldStore(t *testing.T) {
	store := NewShieldStore()
	if store.restrictions == nil {
		t.Error("restrictions map should be initialized")
	}
	if store.riskCounts == nil {
		t.Error("riskCounts map should be initialized")
	}
	if store.lastDecision == nil {
		t.Error("lastDecision map should be initialized")
	}
	if store.lastDecisionTime == nil {
		t.Error("lastDecisionTime map should be initialized")
	}
}

func TestRecordDecisionStoresDecision(t *testing.T) {
	tests := []struct {
		name     string
		agentID  string
		decision string
	}{
		{"allow decision", "agent1", "allow"},
		{"deny decision", "agent2", "deny"},
		{"escalate decision", "agent3", "escalate"},
		{"unknown decision", "agent4", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewShieldStore()
			store.RecordDecision(tc.agentID, tc.decision)
			got := store.GetLastDecision(tc.agentID)
			if got != tc.decision {
				t.Errorf("GetLastDecision() = %v, want %v", got, tc.decision)
			}
		})
	}
}

func TestRecordDecisionStoresTime(t *testing.T) {
	store := NewShieldStore()
	before := time.Now()
	store.RecordDecision("agent1", "allow")
	after := time.Now()

	got := store.GetLastDecisionTime("agent1")
	if got.IsZero() {
		t.Error("GetLastDecisionTime() returned zero time")
	}
	if got.Before(before) || got.After(after) {
		t.Errorf("GetLastDecisionTime() = %v, expected time between %v and %v", got, before, after)
	}
}

func TestGetLastDecisionEmpty(t *testing.T) {
	store := NewShieldStore()
	got := store.GetLastDecision("unknown")
	if got != "" {
		t.Errorf("GetLastDecision() = %v, want empty string", got)
	}
}

func TestGetLastDecisionTimeEmpty(t *testing.T) {
	store := NewShieldStore()
	got := store.GetLastDecisionTime("unknown")
	if !got.IsZero() {
		t.Errorf("GetLastDecisionTime() = %v, want zero time", got)
	}
}

func TestRecordDecisionIncrementsRiskCount(t *testing.T) {
	tests := []struct {
		name     string
		decision string
		increment bool
	}{
		{"deny increments", "deny", true},
		{"escalate increments", "escalate", true},
		{"allow does not increment", "allow", false},
		{"unknown does not increment", "unknown", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewShieldStore()
			store.RecordDecision("agent1", tc.decision)
			got := store.GetRiskCount("agent1")
			want := 0
			if tc.increment {
				want = 1
			}
			if got != want {
				t.Errorf("GetRiskCount() = %v, want %v", got, want)
			}
		})
	}
}

func TestMultipleDecisionsIncrementRiskCount(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")
	store.RecordDecision("agent1", "allow")
	store.RecordDecision("agent1", "deny")

	got := store.GetRiskCount("agent1")
	want := 3
	if got != want {
		t.Errorf("GetRiskCount() = %v, want %v", got, want)
	}
}

func TestGetRiskCountEmpty(t *testing.T) {
	store := NewShieldStore()
	got := store.GetRiskCount("unknown")
	if got != 0 {
		t.Errorf("GetRiskCount() = %v, want 0", got)
	}
}

func TestRestrict(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent1", "test reason")

	r := store.GetRestriction("agent1")
	if r == nil {
		t.Fatal("GetRestriction() returned nil")
	}
	if r.AgentID != "agent1" {
		t.Errorf("AgentID = %v, want agent1", r.AgentID)
	}
	if !r.Restricted {
		t.Error("Restricted = false, want true")
	}
	if r.Reason != "test reason" {
		t.Errorf("Reason = %v, want test reason", r.Reason)
	}
	if r.Since.IsZero() {
		t.Error("Since is zero time")
	}
}

func TestUnrestrict(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent1", "test reason")
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")

	store.Unrestrict("agent1")

	r := store.GetRestriction("agent1")
	if r != nil {
		t.Error("GetRestriction() should return nil after Unrestrict")
	}

	got := store.GetRiskCount("agent1")
	if got != 0 {
		t.Errorf("GetRiskCount() = %v, want 0 after Unrestrict", got)
	}

	if store.GetLastDecision("agent1") != "" {
		t.Error("lastDecision should be cleared after Unrestrict")
	}

	if !store.GetLastDecisionTime("agent1").IsZero() {
		t.Error("lastDecisionTime should be cleared after Unrestrict")
	}
}

func TestUnrestrictNonExistent(t *testing.T) {
	store := NewShieldStore()
	store.Unrestrict("unknown")
}

func TestGetRestriction(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*ShieldStore)
		agentID string
		want    bool
	}{
		{
			name:    "restricted agent",
			setup:   func(s *ShieldStore) { s.Restrict("agent1", "reason") },
			agentID: "agent1",
			want:    true,
		},
		{
			name:    "unrestricted agent",
			setup:   func(s *ShieldStore) { s.Restrict("agent1", "reason") },
			agentID: "agent2",
			want:    false,
		},
		{
			name:    "empty store",
			setup:   func(s *ShieldStore) {},
			agentID: "unknown",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewShieldStore()
			tc.setup(store)
			r := store.GetRestriction(tc.agentID)
			if (r != nil) != tc.want {
				t.Errorf("GetRestriction() returned nil = %v, want nil = %v", r == nil, !tc.want)
			}
		})
	}
}

func TestIsRestricted(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*ShieldStore)
		agentID string
		want    bool
	}{
		{
			name:    "restricted agent returns true",
			setup:   func(s *ShieldStore) { s.Restrict("agent1", "reason") },
			agentID: "agent1",
			want:    true,
		},
		{
			name:    "unrestricted agent returns false",
			setup:   func(s *ShieldStore) {},
			agentID: "agent1",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewShieldStore()
			tc.setup(store)
			got := store.IsRestricted(tc.agentID)
			if got != tc.want {
				t.Errorf("IsRestricted() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetAllRestricted(t *testing.T) {
	store := NewShieldStore()
	store.Restrict("agent1", "reason1")
	store.Restrict("agent2", "reason2")

	restricted := store.GetAllRestricted()
	if len(restricted) != 2 {
		t.Fatalf("GetAllRestricted() returned %v agents, want 2", len(restricted))
	}

	found := make(map[string]bool)
	for _, r := range restricted {
		found[r.AgentID] = true
	}
	if !found["agent1"] || !found["agent2"] {
		t.Error("GetAllRestricted() missing expected agents")
	}
}

func TestGetAllRestrictedEmpty(t *testing.T) {
	store := NewShieldStore()
	restricted := store.GetAllRestricted()
	if len(restricted) != 0 {
		t.Errorf("GetAllRestricted() returned %v agents, want 0", len(restricted))
	}
}

func TestGetStats(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")
	store.Restrict("agent1", "test reason")

	stats := store.GetStats("agent1")
	if stats.Restricted != true {
		t.Error("Restricted = false, want true")
	}
	if stats.RiskCount != 2 {
		t.Errorf("RiskCount = %v, want 2", stats.RiskCount)
	}
	if stats.LastDecision != "escalate" {
		t.Errorf("LastDecision = %v, want escalate", stats.LastDecision)
	}
	if stats.LastDecisionAt.IsZero() {
		t.Error("LastDecisionAt is zero")
	}
}

func TestGetStatsUnrestricted(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "allow")

	stats := store.GetStats("agent1")
	if stats.Restricted != false {
		t.Error("Restricted = true, want false")
	}
	if stats.RiskCount != 0 {
		t.Errorf("RiskCount = %v, want 0", stats.RiskCount)
	}
	if stats.LastDecision != "allow" {
		t.Errorf("LastDecision = %v, want allow", stats.LastDecision)
	}
}

func TestGetStatsNonExistent(t *testing.T) {
	store := NewShieldStore()

	stats := store.GetStats("unknown")
	if stats.Restricted != false {
		t.Error("Restricted = true, want false")
	}
	if stats.RiskCount != 0 {
		t.Errorf("RiskCount = %v, want 0", stats.RiskCount)
	}
	if stats.LastDecision != "" {
		t.Errorf("LastDecision = %v, want empty", stats.LastDecision)
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := NewShieldStore()
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			store.RecordDecision("agent1", "deny")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			store.GetLastDecision("agent1")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			store.GetRiskCount("agent1")
		}
		done <- true
	}()

	<-done
	<-done
	<-done

	if store.GetRiskCount("agent1") != 100 {
		t.Errorf("GetRiskCount() = %v, want 100", store.GetRiskCount("agent1"))
	}
}
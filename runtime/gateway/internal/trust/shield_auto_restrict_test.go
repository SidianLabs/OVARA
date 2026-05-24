package trust

import "testing"

func TestAutoRestrictAfterRepeatedRisk_TriggersOnThreshold(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")
	store.RecordDecision("agent1", "deny")

	got := store.AutoRestrictAfterRepeatedRisk("agent1", threshold)
	if !got {
		t.Error("AutoRestrictAfterRepeatedRisk() = false, want true after 3 risk events")
	}

	if !store.IsRestricted("agent1") {
		t.Error("IsRestricted() = false, want true after auto-restriction")
	}

	restriction := store.GetRestriction("agent1")
	if restriction == nil {
		t.Fatal("GetRestriction() returned nil")
	}
	if restriction.Reason != "auto_restricted_after_3_risk_events" {
		t.Errorf("Reason = %v, want auto_restricted_after_3_risk_events", restriction.Reason)
	}
}

func TestAutoRestrictAfterRepeatedRisk_DoesNotTriggerBeforeThreshold(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")

	got := store.AutoRestrictAfterRepeatedRisk("agent1", threshold)
	if got {
		t.Error("AutoRestrictAfterRepeatedRisk() = true, want false before threshold reached")
	}

	if store.IsRestricted("agent1") {
		t.Error("IsRestricted() = true, want false before threshold reached")
	}
}

func TestAutoRestrictAfterRepeatedRisk_ReturnsFalseIfAlreadyRestricted(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")

	store.Restrict("agent1", "manual_restriction")

	got := store.AutoRestrictAfterRepeatedRisk("agent1", threshold)
	if got {
		t.Error("AutoRestrictAfterRepeatedRisk() = true, want false when already restricted")
	}
}

func TestAutoRestrictAfterRepeatedRisk_DoesNotReRestrict(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")

	store.AutoRestrictAfterRepeatedRisk("agent1", threshold)

	if store.GetRiskCount("agent1") != 3 {
		t.Errorf("RiskCount = %v, want 3 (should not be cleared)", store.GetRiskCount("agent1"))
	}

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")

	got := store.AutoRestrictAfterRepeatedRisk("agent1", threshold)
	if got {
		t.Error("AutoRestrictAfterRepeatedRisk() = true, want false when already restricted")
	}
}

func TestShouldAutoRestrict_ReturnsTrueWhenThresholdMet(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")
	store.RecordDecision("agent1", "deny")

	got := store.ShouldAutoRestrict("agent1", threshold)
	if !got {
		t.Error("ShouldAutoRestrict() = false, want true when risk count >= threshold")
	}
}

func TestShouldAutoRestrict_ReturnsFalseBelowThreshold(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "escalate")

	got := store.ShouldAutoRestrict("agent1", threshold)
	if got {
		t.Error("ShouldAutoRestrict() = true, want false when risk count < threshold")
	}
}

func TestShouldAutoRestrict_ReturnsFalseWhenAlreadyRestricted(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")
	store.RecordDecision("agent1", "deny")

	store.Restrict("agent1", "manual_restriction")

	got := store.ShouldAutoRestrict("agent1", threshold)
	if got {
		t.Error("ShouldAutoRestrict() = true, want false when agent is already restricted")
	}
}

func TestShouldAutoRestrict_ReturnsFalseForNewAgent(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	got := store.ShouldAutoRestrict("unknown", threshold)
	if got {
		t.Error("ShouldAutoRestrict() = true for new agent, want false")
	}
}

func TestRecordDecisionIncrementsRiskCountForDeny(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "deny")
	if store.GetRiskCount("agent1") != 1 {
		t.Errorf("GetRiskCount() = %v, want 1 after deny", store.GetRiskCount("agent1"))
	}
}

func TestRecordDecisionIncrementsRiskCountForEscalate(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "escalate")
	if store.GetRiskCount("agent1") != 1 {
		t.Errorf("GetRiskCount() = %v, want 1 after escalate", store.GetRiskCount("agent1"))
	}
}

func TestRecordDecisionDoesNotIncrementForAllow(t *testing.T) {
	store := NewShieldStore()
	store.RecordDecision("agent1", "allow")
	if store.GetRiskCount("agent1") != 0 {
		t.Errorf("GetRiskCount() = %v, want 0 after allow", store.GetRiskCount("agent1"))
	}
}

func TestAutoRestrictWorkflow(t *testing.T) {
	store := NewShieldStore()
	threshold := 3

	if store.ShouldAutoRestrict("agent1", threshold) {
		t.Error("ShouldAutoRestrict() = true before any decisions, want false")
	}

	store.RecordDecision("agent1", "deny")
	if store.ShouldAutoRestrict("agent1", threshold) {
		t.Error("ShouldAutoRestrict() = true with 1 risk, want false")
	}

	store.RecordDecision("agent1", "escalate")
	if store.ShouldAutoRestrict("agent1", threshold) {
		t.Error("ShouldAutoRestrict() = true with 2 risks, want false")
	}

	store.RecordDecision("agent1", "deny")
	if !store.ShouldAutoRestrict("agent1", threshold) {
		t.Error("ShouldAutoRestrict() = false with 3 risks, want true")
	}

	applied := store.AutoRestrictAfterRepeatedRisk("agent1", threshold)
	if !applied {
		t.Error("AutoRestrictAfterRepeatedRisk() = false, want true")
	}

	if !store.IsRestricted("agent1") {
		t.Error("IsRestricted() = false, want true after auto-restriction")
	}

	if store.ShouldAutoRestrict("agent1", threshold) {
		t.Error("ShouldAutoRestrict() = true after restriction, want false")
	}

	if store.AutoRestrictAfterRepeatedRisk("agent1", threshold) {
		t.Error("AutoRestrictAfterRepeatedRisk() = true when already restricted, want false")
	}
}
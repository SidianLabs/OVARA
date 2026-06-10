package degradation

import (
	"math"
	"testing"
)

func TestDegradationModel_InitialScore(t *testing.T) {
	dm := NewDegradationModel()
	if dm.GetScore("agent1") != 1.0 {
		t.Errorf("initial score = %v, want 1.0", dm.GetScore("agent1"))
	}
}

func TestDegradationModel_AllowDecision(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "allow")
	if dm.GetScore("agent1") != 1.0 {
		t.Errorf("score after allow = %v, want 1.0", dm.GetScore("agent1"))
	}
}

func TestDegradationModel_DenyDecay(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	score := dm.GetScore("agent1")
	if score >= 1.0 {
		t.Errorf("score after deny = %v, should be < 1.0", score)
	}
	if score <= 0.0 {
		t.Errorf("score after single deny = %v, should be > 0.0", score)
	}
}

func TestDegradationModel_StreakAcceleration(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	score1 := dm.GetScore("agent1")

	dm.RecordDecision("agent1", "deny")
	score2 := dm.GetScore("agent1")

	dm.RecordDecision("agent1", "deny")
	score3 := dm.GetScore("agent1")

	drop1 := 1.0 - score1
	drop2 := score1 - score2
	drop3 := score2 - score3

	if drop2 <= drop1 {
		t.Error("second deny should degrade faster than first (streak accel)")
	}
	if drop3 <= drop2 {
		t.Error("third deny should degrade faster than second (streak accel)")
	}
}

func TestDegradationModel_Recovery(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	lowScore := dm.GetScore("agent1")

	dm.RecordDecision("agent1", "allow")
	higherScore := dm.GetScore("agent1")

	if higherScore <= lowScore {
		t.Errorf("score should increase after recovery: %v <= %v", higherScore, lowScore)
	}
}

func TestDegradationModel_RecoveryStreakReset(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "allow")
	scoreAfterAllow := dm.GetScore("agent1")

	dm.RecordDecision("agent1", "deny")
	scoreAfterResetDeny := dm.GetScore("agent1")
	dropAfterReset := scoreAfterAllow - scoreAfterResetDeny
	dropFraction := dropAfterReset / scoreAfterAllow

	if dropFraction > 0.16 || dropFraction < 0.14 {
		t.Errorf("drop fraction after reset = %v, want ~0.15 (base decay)", dropFraction)
	}
}

func TestDegradationModel_MinScore(t *testing.T) {
	dm := NewDegradationModel()
	for i := 0; i < 100; i++ {
		dm.RecordDecision("agent1", "deny")
	}
	score := dm.GetScore("agent1")
	if score < 0.0 {
		t.Errorf("score = %v, should not go below 0.0", score)
	}
}

func TestDegradationModel_MaxScore(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "allow")
	dm.RecordDecision("agent1", "allow")
	score := dm.GetScore("agent1")
	if score > 1.0 {
		t.Errorf("score = %v, should not exceed 1.0", score)
	}
}

func TestDegradationModel_Level(t *testing.T) {
	dm := NewDegradationModel()

	if dm.GetLevel("agent1") != "high" {
		t.Errorf("level = %v, want high", dm.GetLevel("agent1"))
	}

	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent1", "deny")

	level := dm.GetLevel("agent1")
	if level == "high" {
		t.Error("level should degrade after repeated denies")
	}
}

func TestDegradationModel_MultipleAgents(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "deny")
	dm.RecordDecision("agent2", "allow")

	if dm.GetScore("agent1") >= dm.GetScore("agent2") {
		t.Error("agent1 should have lower score than agent2")
	}
}

func TestDegradationModel_EscalateDecay(t *testing.T) {
	dm := NewDegradationModel()
	dm.RecordDecision("agent1", "escalate")
	score := dm.GetScore("agent1")
	if score >= 1.0 {
		t.Errorf("escalate should decay score: %v", score)
	}

	dm2 := NewDegradationModel()
	dm2.RecordDecision("agent1", "deny")
	denyScore := dm2.GetScore("agent1")

	if math.Abs(score-denyScore) > 1e-10 {
		t.Errorf("escalate and deny should decay equally: escalate=%v deny=%v", score, denyScore)
	}
}

package trust

import (
	"testing"
)

func TestDegradationModel_InitialScore(t *testing.T) {
	cfg := DefaultDegradationConfig()
	dm := NewDegradationModel(cfg)

	score := dm.CurrentScore("new-agent")
	if score != cfg.InitialScore {
		t.Errorf("initial score = %f, want %f", score, cfg.InitialScore)
	}
}

func TestDegradationModel_RecordRiskReducesScore(t *testing.T) {
	cfg := DefaultDegradationConfig()
	cfg.PenaltyFactor = 0.5 // Strong penalty for test visibility
	dm := NewDegradationModel(cfg)

	initial := dm.CurrentScore("agent-001")
	score, degraded := dm.RecordRisk("agent-001")

	if score >= initial {
		t.Errorf("score = %f, should be less than initial %f", score, initial)
	}
	if !degraded {
		t.Error("should be degraded with high penalty")
	}
}

func TestDegradationModel_RecordCleanRecovers(t *testing.T) {
	cfg := DefaultDegradationConfig()
	cfg.PenaltyFactor = 0.5
	dm := NewDegradationModel(cfg)

	dm.RecordRisk("agent-001")
	degradedScore := dm.CurrentScore("agent-001")

	// Multiple clean actions should recover
	for i := 0; i < 20; i++ {
		dm.RecordClean("agent-001")
	}
	recoveredScore := dm.CurrentScore("agent-001")

	if recoveredScore <= degradedScore {
		t.Errorf("recovered score %f should be > degraded score %f", recoveredScore, degradedScore)
	}
}

func TestDegradationModel_StreakAcceleratedDecay(t *testing.T) {
	cfg := DefaultDegradationConfig()
	cfg.StreakThreshold = 3
	cfg.PenaltyFactor = 0.7
	dm := NewDegradationModel(cfg)

	singleRiskScore, _ := dm.RecordRisk("agent-001")
	dm.ResetScore("agent-001")

	// 5 consecutive risks should produce lower score than 1
	for i := 0; i < 5; i++ {
		dm.RecordRisk("agent-002")
	}
	streakScore, _ := dm.RecordRisk("agent-002") // this is the 6th

	if streakScore >= singleRiskScore {
		t.Errorf("streak score %f should be < single risk score %f", streakScore, singleRiskScore)
	}
}

func TestDegradationModel_ScoreFloor(t *testing.T) {
	cfg := DefaultDegradationConfig()
	cfg.MinScore = 0.2
	cfg.PenaltyFactor = 0.01
	dm := NewDegradationModel(cfg)

	for i := 0; i < 100; i++ {
		dm.RecordRisk("agent-001")
	}

	score := dm.CurrentScore("agent-001")
	if score < cfg.MinScore {
		t.Errorf("score %f below min %f", score, cfg.MinScore)
	}
}

func TestDegradationModel_GetState(t *testing.T) {
	cfg := DefaultDegradationConfig()
	dm := NewDegradationModel(cfg)

	dm.RecordRisk("agent-001")
	dm.RecordRisk("agent-001")

	state := dm.GetState("agent-001")
	if state.RiskStreak != 2 {
		t.Errorf("risk_streak = %d, want 2", state.RiskStreak)
	}
	if !state.IsDegraded && dm.CurrentScore("agent-001") < 0.5 {
		t.Error("should be degraded when score < 0.5")
	}
}

func TestDegradationModel_ResetScore(t *testing.T) {
	cfg := DefaultDegradationConfig()
	dm := NewDegradationModel(cfg)

	dm.RecordRisk("agent-001")
	dm.ResetScore("agent-001")

	score := dm.CurrentScore("agent-001")
	if score != cfg.InitialScore {
		t.Errorf("after reset: score = %f, want %f", score, cfg.InitialScore)
	}
	state := dm.GetState("agent-001")
	if state.RiskStreak != 0 {
		t.Errorf("after reset: risk_streak = %d, want 0", state.RiskStreak)
	}
}

func TestDegradationModel_ConcurrentAccess(t *testing.T) {
	cfg := DefaultDegradationConfig()
	dm := NewDegradationModel(cfg)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				dm.RecordRisk("agent-001")
				dm.RecordClean("agent-001")
				dm.CurrentScore("agent-001")
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic, and score should be sensible
	score := dm.CurrentScore("agent-001")
	if score < 0 || score > 1.0 {
		t.Errorf("score out of bounds: %f", score)
	}
}

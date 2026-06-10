package drift

import "testing"

func TestDriftDetector_NoActions(t *testing.T) {
	dd := NewDriftDetector(10, 0.5)
	r := dd.CheckDrift("unknown_agent")
	if r.Drifting {
		t.Error("no actions should not be drifting")
	}
	if r.Confidence != 0 {
		t.Errorf("confidence = %v, want 0", r.Confidence)
	}
}

func TestDriftDetector_AllClean(t *testing.T) {
	dd := NewDriftDetector(5, 0.5)
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "read", false)
	}
	r := dd.CheckDrift("agent1")
	if r.Drifting {
		t.Error("all clean actions should not be drifting")
	}
	if r.Confidence != 0 {
		t.Errorf("confidence = %v, want 0", r.Confidence)
	}
}

func TestDriftDetector_AllRisky(t *testing.T) {
	dd := NewDriftDetector(5, 0.5)
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "write", true)
	}
	r := dd.CheckDrift("agent1")
	if !r.Drifting {
		t.Error("all risky actions should be drifting")
	}
	if r.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", r.Confidence)
	}
}

func TestDriftDetector_Threshold(t *testing.T) {
	dd := NewDriftDetector(10, 0.5)
	for i := 0; i < 4; i++ {
		dd.RecordAction("agent1", "write", true)
	}
	for i := 0; i < 6; i++ {
		dd.RecordAction("agent1", "read", false)
	}
	r := dd.CheckDrift("agent1")
	if r.Drifting {
		t.Error("40% risky should not exceed 50% threshold")
	}
	if r.Confidence != 0.4 {
		t.Errorf("confidence = %v, want 0.4", r.Confidence)
	}
}

func TestDriftDetector_SlidingWindow(t *testing.T) {
	dd := NewDriftDetector(5, 0.5)
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "write", true)
	}
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "read", false)
	}
	r := dd.CheckDrift("agent1")
	if r.Drifting {
		t.Error("old risky actions should be evicted from window")
	}
	if r.Confidence != 0 {
		t.Errorf("confidence = %v, want 0", r.Confidence)
	}
}

func TestDriftDetector_WindowCount(t *testing.T) {
	dd := NewDriftDetector(10, 0.5)
	for i := 0; i < 3; i++ {
		dd.RecordAction("agent1", "read", false)
	}
	r := dd.CheckDrift("agent1")
	if r.Window != 3 {
		t.Errorf("window = %d, want 3", r.Window)
	}
}

func TestDriftDetector_MultipleAgents(t *testing.T) {
	dd := NewDriftDetector(5, 0.5)
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "write", true)
		dd.RecordAction("agent2", "read", false)
	}
	r1 := dd.CheckDrift("agent1")
	r2 := dd.CheckDrift("agent2")
	if !r1.Drifting {
		t.Error("agent1 should be drifting")
	}
	if r2.Drifting {
		t.Error("agent2 should not be drifting")
	}
}

func TestDriftDetector_ThresholdExactly(t *testing.T) {
	dd := NewDriftDetector(10, 0.5)
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "write", true)
	}
	for i := 0; i < 5; i++ {
		dd.RecordAction("agent1", "read", false)
	}
	r := dd.CheckDrift("agent1")
	if !r.Drifting {
		t.Error("exactly at threshold should be drifting")
	}
}

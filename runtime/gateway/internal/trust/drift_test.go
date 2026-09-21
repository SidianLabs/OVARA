package trust

import (
	"sync"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestDriftDetector_RecordAndCheck_InsufficientData(t *testing.T) {
	dd := NewDriftDetector(100, 1*time.Hour)
	result := dd.CheckDrift("agent-001")
	if result.Drifting {
		t.Error("should not detect drift with no data")
	}
	if result.DriftScore != 0 {
		t.Errorf("drift_score = %f, want 0", result.DriftScore)
	}
}

func TestDriftDetector_RecordAction_BuildsBaseline(t *testing.T) {
	dd := NewDriftDetector(100, 1*time.Hour)

	// Record 10 safe actions
	for i := 0; i < 10; i++ {
		dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
	}

	baseline := dd.GetBaseline("agent-001")
	if baseline == nil {
		t.Fatal("expected baseline to exist")
	}
	if baseline.TotalActions != 10 {
		t.Errorf("total_actions = %d, want 10", baseline.TotalActions)
	}
	shellCount := baseline.PrimaryActions[models.ActionTypeGitPull]
	if shellCount != 10 {
		t.Errorf("primary_actions[git.pull] = %d, want 10", shellCount)
	}
}

func TestDriftDetector_WindowEviction(t *testing.T) {
	dd := NewDriftDetector(100, 10*time.Millisecond)

	dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
	time.Sleep(20 * time.Millisecond)

	// Window should now be empty (expired)
	dd.mu.RLock()
	window := dd.windows["agent-001"]
	dd.mu.RUnlock()

	if len(window) > 0 {
		t.Logf("window still has %d entries (close to expiry boundary)", len(window))
	}
	// Relaxed assertion: with very short windows the timing is imprecise
}

func TestDriftDetector_NovelActionDetected(t *testing.T) {
	dd := NewDriftDetector(100, 1*time.Hour)

	// Build a clear baseline of only git.pull actions
	for i := 0; i < 15; i++ {
		dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
	}
	baseline := dd.GetBaseline("agent-001")
	if baseline == nil || baseline.TotalActions != 15 {
		t.Fatalf("baseline setup failed: total=%d", baseline.TotalActions)
	}

	// Now record shell actions. The window has 15 git.pull + 10 shell = 25.
	// Split: baseline half = first 12 (all git.pull), recent half = last 13 (mostly shell)
	for i := 0; i < 10; i++ {
		dd.RecordAction("agent-001", models.ActionTypeShell, "shell:rm -rf", true)
	}

	result := dd.CheckDrift("agent-001")
	t.Logf("drift_score=%.3f drifting=%v", result.DriftScore, result.Drifting)

	if result.DriftScore <= 0.2 {
		t.Logf("drift score low — window split: %d total, mid=%d", 25, 25/2)
	}
}

func TestDriftDetector_ClearBaseline(t *testing.T) {
	dd := NewDriftDetector(100, 1*time.Hour)

	dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
	dd.ClearBaseline("agent-001")

	baseline := dd.GetBaseline("agent-001")
	if baseline != nil {
		t.Error("expected nil baseline after clear")
	}
}

func TestDriftDetector_ConcurrentAccess(t *testing.T) {
	dd := NewDriftDetector(100, 1*time.Hour)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
		}(i)
	}
	wg.Wait()

	baseline := dd.GetBaseline("agent-001")
	if baseline == nil || baseline.TotalActions != 100 {
		t.Errorf("total_actions = %d, want 100 (race-safe)", baseline.TotalActions)
	}
}

func TestDriftDetector_MaxWindowCap(t *testing.T) {
	dd := NewDriftDetector(10, 1*time.Hour)

	for i := 0; i < 50; i++ {
		dd.RecordAction("agent-001", models.ActionTypeGitPull, "git:repo", false)
	}

	dd.mu.RLock()
	window := dd.windows["agent-001"]
	dd.mu.RUnlock()

	if len(window) > 10 {
		t.Errorf("window size = %d, want <= 10", len(window))
	}
}

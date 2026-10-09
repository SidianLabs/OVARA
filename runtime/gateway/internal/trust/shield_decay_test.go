package trust

import (
	"testing"
	"time"
)

// Default behaviour is unchanged: lifetime counts, restrictions last until lifted.
func TestShield_DefaultsKeepLifetimeCounts(t *testing.T) {
	s := NewShieldStore()
	for i := 0; i < 4; i++ {
		s.RecordDecision("a", "deny")
	}
	time.Sleep(20 * time.Millisecond)
	if got := s.GetRiskCount("a"); got != 4 {
		t.Fatalf("without a window, risk is a lifetime count; got %d", got)
	}
}

// With a window, old denials stop counting, so an agent that hit a few blocked
// sites earlier is not penalised forever.
func TestShield_RiskEventsAgeOut(t *testing.T) {
	s := NewShieldStore()
	s.SetRiskWindow(80 * time.Millisecond)
	for i := 0; i < 3; i++ {
		s.RecordDecision("a", "deny")
	}
	if got := s.GetRiskCount("a"); got != 3 {
		t.Fatalf("fresh events must count, got %d", got)
	}
	time.Sleep(150 * time.Millisecond)
	if got := s.GetRiskCount("a"); got != 0 {
		t.Fatalf("events older than the window must stop counting, got %d", got)
	}
}

// An automatic restriction lifts itself; the agent is usable again without an
// operator, and is not instantly re-restricted by stale history.
func TestShield_AutoRestrictionExpires(t *testing.T) {
	s := NewShieldStore()
	s.SetRiskWindow(60 * time.Millisecond)
	s.SetAutoRestrictTTL(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		s.RecordDecision("a", "deny")
	}
	if !s.AutoRestrictAfterRepeatedRisk("a", 3) || !s.IsRestricted("a") {
		t.Fatal("three denials should restrict the agent")
	}
	time.Sleep(200 * time.Millisecond)
	if s.IsRestricted("a") {
		t.Fatal("an automatic restriction must lift itself")
	}
	if s.ShouldAutoRestrict("a", 3) {
		t.Fatal("stale history must not re-restrict the agent straight away")
	}
}

// A restriction an operator sets by hand never times out.
func TestShield_ManualRestrictionIsPermanentUntilLifted(t *testing.T) {
	s := NewShieldStore()
	s.SetRiskWindow(20 * time.Millisecond)
	s.SetAutoRestrictTTL(20 * time.Millisecond)
	s.Restrict("a", "operator decided")
	time.Sleep(100 * time.Millisecond)
	if !s.IsRestricted("a") {
		t.Fatal("a manual restriction must not expire on its own")
	}
	s.Unrestrict("a")
	if s.IsRestricted("a") {
		t.Fatal("Unrestrict must lift it")
	}
}

package chain_detection

import (
	"testing"
	"time"
)

func TestChainDetector_NoRecords(t *testing.T) {
	cd := NewChainDetector()
	s := cd.DetectSuspiciousPatterns("agent1")
	if len(s) != 0 {
		t.Error("no records should produce no suspicions")
	}
}

func TestChainDetector_NormalChain(t *testing.T) {
	cd := NewChainDetector()
	cd.RecordChain("agent1", "hash_abc", 3)
	s := cd.DetectSuspiciousPatterns("agent1")
	if len(s) != 0 {
		t.Error("normal chain should not produce suspicions")
	}
}

func TestChainDetector_SelfDelegation(t *testing.T) {
	cd := NewChainDetector()
	cd.RecordChain("agent1", "hash_self", 0)
	s := cd.DetectSuspiciousPatterns("agent1")

	found := false
	for _, sus := range s {
		if sus.Type == "self_delegation" {
			found = true
			if sus.Severity != "critical" {
				t.Errorf("self-delegation severity = %v, want critical", sus.Severity)
			}
		}
	}
	if !found {
		t.Error("expected self_delegation suspicion")
	}
}

func TestChainDetector_ExcessiveDepth(t *testing.T) {
	cd := NewChainDetector()
	cd.RecordChain("agent1", "hash_deep", 8)
	s := cd.DetectSuspiciousPatterns("agent1")

	found := false
	for _, sus := range s {
		if sus.Type == "excessive_depth" {
			found = true
			if sus.Severity != "high" {
				t.Errorf("excessive depth severity = %v, want high", sus.Severity)
			}
		}
	}
	if !found {
		t.Error("expected excessive_depth suspicion")
	}
}

func TestChainDetector_RapidReDelegation(t *testing.T) {
	cd := NewChainDetector()
	cd.rapidWindowSec = 60
	cd.rapidThreshold = 3

	for i := 0; i < 3; i++ {
		cd.RecordChain("agent1", "hash_"+string(rune('a'+i)), 2)
	}

	s := cd.DetectSuspiciousPatterns("agent1")
	found := false
	for _, sus := range s {
		if sus.Type == "rapid_redelegation" {
			found = true
		}
	}
	if !found {
		t.Error("expected rapid_redelegation suspicion")
	}
}

func TestChainDetector_RapidNotTriggered(t *testing.T) {
	cd := NewChainDetector()
	cd.rapidWindowSec = 1
	cd.rapidThreshold = 3

	cd.RecordChain("agent1", "hash1", 2)

	time.Sleep(1500 * time.Millisecond)

	cd.RecordChain("agent1", "hash2", 2)

	s := cd.DetectSuspiciousPatterns("agent1")
	for _, sus := range s {
		if sus.Type == "rapid_redelegation" {
			t.Error("should not detect rapid re-delegation outside window")
		}
	}
}

func TestChainDetector_MultipleIssues(t *testing.T) {
	cd := NewChainDetector()
	cd.rapidThreshold = 2
	cd.RecordChain("agent1", "hash_self", 0)
	cd.RecordChain("agent1", "hash_deep", 10)
	cd.RecordChain("agent1", "hash_another", 2)

	s := cd.DetectSuspiciousPatterns("agent1")
	if len(s) < 2 {
		t.Errorf("expected multiple suspicions, got %d", len(s))
	}
}

func TestChainDetector_MultipleAgents(t *testing.T) {
	cd := NewChainDetector()
	cd.RecordChain("agent1", "hash1", 2)
	cd.RecordChain("agent2", "hash_self", 0)

	s1 := cd.DetectSuspiciousPatterns("agent1")
	s2 := cd.DetectSuspiciousPatterns("agent2")

	if len(s1) != 0 {
		t.Error("agent1 should have no suspicions")
	}
	if len(s2) == 0 {
		t.Error("agent2 should have suspicions")
	}
}

func TestChainDetector_SortedBySeverity(t *testing.T) {
	cd := NewChainDetector()
	cd.rapidThreshold = 2
	cd.RecordChain("agent1", "hash_self", 0)
	cd.RecordChain("agent1", "hash_deep", 10)
	cd.RecordChain("agent1", "hash2", 1)

	s := cd.DetectSuspiciousPatterns("agent1")
	for i := 1; i < len(s); i++ {
		if s[i].Severity > s[i-1].Severity {
			t.Error("suspicions should be sorted by severity descending")
		}
	}
}

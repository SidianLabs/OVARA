package trust

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestChainDetector_ExcessiveDepth(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 3)

	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "a", SubjectID: "b"},
			{Issuer: "b", SubjectID: "c"},
			{Issuer: "c", SubjectID: "d"},
			{Issuer: "d", SubjectID: "e"},
		},
		Depth: 4,
	}

	cd.RecordChain("agent-001", chain)
	suspicions := cd.DetectSuspiciousPatterns("agent-001")

	foundDepth := false
	for _, s := range suspicions {
		if s.Code == "excessive_delegation_depth" {
			foundDepth = true
			break
		}
	}
	if !foundDepth {
		t.Error("expected excessive_delegation_depth detection")
	}
}

func TestChainDetector_SelfDelegation(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)

	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "self", SubjectID: "self"},
		},
		Depth: 1,
	}

	cd.RecordChain("agent-001", chain)
	suspicions := cd.DetectSuspiciousPatterns("agent-001")

	found := false
	for _, s := range suspicions {
		if s.Code == "self_delegation" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected self_delegation detection")
	}
}

func TestChainDetector_NoSuspicion(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)

	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-001"},
			{Issuer: "agent-001", SubjectID: "agent-002"},
		},
		Depth: 2,
	}

	cd.RecordChain("agent-001", chain)
	suspicions := cd.DetectSuspiciousPatterns("agent-001")

	if len(suspicions) > 0 {
		t.Errorf("expected no suspicions, got %d: %v", len(suspicions), suspicions)
	}
}

func TestChainDetector_EmptyAgent(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)
	suspicions := cd.DetectSuspiciousPatterns("unknown-agent")
	if len(suspicions) > 0 {
		t.Error("expected no suspicions for unknown agent")
	}
}

func TestChainDetector_IssuerConcentration(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)

	// Record many chains with the same issuer
	for i := 0; i < 10; i++ {
		chain := &models.DelegationChain{
			Authorities: []models.Authority{
				{Issuer: "concentrated-issuer", SubjectID: "agent-001"},
			},
			Depth: 1,
		}
		cd.RecordChain("agent-001", chain)
	}

	suspicions := cd.DetectSuspiciousPatterns("agent-001")
	found := false
	for _, s := range suspicions {
		if s.Code == "issuer_concentration" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected issuer_concentration detection")
	}
}

func TestChainDetector_RapidRedelegation(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)

	for i := 0; i < 5; i++ {
		chain := &models.DelegationChain{
			Authorities: []models.Authority{
				{Issuer: "a", SubjectID: "b"},
				{Issuer: "b", SubjectID: "c"},
			},
			Depth: 2,
		}
		cd.RecordChain("agent-001", chain)
	}

	suspicions := cd.DetectSuspiciousPatterns("agent-001")
	found := false
	for _, s := range suspicions {
		if s.Code == "rapid_redelegation" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rapid_redelegation detection")
	}
}

func TestChainDetector_NilChain(t *testing.T) {
	cd := NewChainDetector(50, 1*time.Hour, 5)
	// Should not panic
	cd.RecordChain("agent-001", nil)
	suspicions := cd.DetectSuspiciousPatterns("agent-001")
	if len(suspicions) > 0 {
		t.Error("expected no suspicions for nil chain")
	}
}

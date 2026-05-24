package trust

import (
	"fmt"
	"sync"
	"time"
)

type ShieldStore struct {
	mu           sync.RWMutex
	restrictions map[string]*Restriction
	riskCounts    map[string]int
	lastDecision map[string]string
	lastDecisionTime map[string]time.Time
}

type Restriction struct {
	AgentID    string
	Restricted bool
	Reason     string
	Since      time.Time
}

func NewShieldStore() *ShieldStore {
	return &ShieldStore{
		restrictions: make(map[string]*Restriction),
		riskCounts:   make(map[string]int),
		lastDecision: make(map[string]string),
		lastDecisionTime: make(map[string]time.Time),
	}
}

func (s *ShieldStore) RecordDecision(agentID, decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastDecision[agentID] = decision
	s.lastDecisionTime[agentID] = time.Now()

	if decision == "deny" || decision == "escalate" {
		s.riskCounts[agentID]++
	}
}

func (s *ShieldStore) GetLastDecision(agentID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastDecision[agentID]
}

func (s *ShieldStore) GetLastDecisionTime(agentID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.lastDecisionTime[agentID]; ok {
		return t
	}
	return time.Time{}
}

func (s *ShieldStore) GetRiskCount(agentID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.riskCounts[agentID]
}

func (s *ShieldStore) Restrict(agentID, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restrictions[agentID] = &Restriction{
		AgentID:    agentID,
		Restricted: true,
		Reason:     reason,
		Since:      time.Now(),
	}
}

func (s *ShieldStore) Unrestrict(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.restrictions, agentID)
	delete(s.riskCounts, agentID)
	delete(s.lastDecision, agentID)
	delete(s.lastDecisionTime, agentID)
}

func (s *ShieldStore) GetRestriction(agentID string) *Restriction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.restrictions[agentID]; ok {
		return r
	}
	return nil
}

func (s *ShieldStore) IsRestricted(agentID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.restrictions[agentID]; ok {
		return r.Restricted
	}
	return false
}

func (s *ShieldStore) GetAllRestricted() []*Restriction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Restriction
	for _, r := range s.restrictions {
		result = append(result, r)
	}
	return result
}

func (s *ShieldStore) GetStats(agentID string) ShieldStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ShieldStats{
		Restricted:     s.restrictions[agentID] != nil,
		RiskCount:      s.riskCounts[agentID],
		LastDecision:   s.lastDecision[agentID],
		LastDecisionAt: s.lastDecisionTime[agentID],
	}
}

func (s *ShieldStore) AutoRestrictAfterRepeatedRisk(agentID string, threshold int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count := s.riskCounts[agentID]; count >= threshold && s.restrictions[agentID] == nil {
		s.restrictions[agentID] = &Restriction{
			AgentID:    agentID,
			Restricted: true,
			Reason:     fmt.Sprintf("auto_restricted_after_%d_risk_events", count),
			Since:      time.Now(),
		}
		return true
	}
	return false
}

func (s *ShieldStore) ShouldAutoRestrict(agentID string, threshold int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.restrictions[agentID] != nil {
		return false
	}
	return s.riskCounts[agentID] >= threshold
}

type ShieldStats struct {
	Restricted     bool
	RiskCount      int
	LastDecision   string
	LastDecisionAt time.Time
}

type ShieldStoreStats struct {
	TotalAgents     int
	RestrictedCount int
	TotalRiskEvents int
}

func (s *ShieldStore) GetAllStats() ShieldStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var totalRisk int
	for _, count := range s.riskCounts {
		totalRisk += count
	}
	return ShieldStoreStats{
		TotalAgents:     len(s.riskCounts),
		RestrictedCount: len(s.restrictions),
		TotalRiskEvents: totalRisk,
	}
}
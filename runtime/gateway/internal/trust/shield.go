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

	// Optional decay. With both zero (the default) the store behaves as it
	// always did: risk counts are lifetime counts and a restriction lasts
	// until an operator unrestricts the agent. The server turns decay on
	// (see SetRiskWindow / SetAutoRestrictTTL) so that an agent that bumped
	// into a few blocked sites is not locked out of everything for good.
	riskWindow time.Duration
	autoTTL    time.Duration
	riskTimes  map[string][]time.Time
}

type Restriction struct {
	AgentID    string
	Restricted bool
	Reason     string
	Since      time.Time
	// ExpiresAt is zero for a restriction that lasts until an operator lifts
	// it (every manual Restrict). Automatic restrictions get an expiry when
	// SetAutoRestrictTTL is configured.
	ExpiresAt time.Time
}

// SetRiskWindow makes risk events count only while they are younger than d
// (0 = lifetime counts, the legacy behaviour).
func (s *ShieldStore) SetRiskWindow(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.riskWindow = d
}

// SetAutoRestrictTTL makes AUTOMATIC restrictions lift themselves after d
// (0 = they last until unrestricted, the legacy behaviour). Restrictions an
// operator sets by hand never expire on their own.
func (s *ShieldStore) SetAutoRestrictTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoTTL = d
}

// pruneLocked drops risk events older than the window and lifts an expired
// automatic restriction. Callers hold s.mu for writing.
func (s *ShieldStore) pruneLocked(agentID string) {
	if s.riskWindow > 0 {
		cutoff := time.Now().Add(-s.riskWindow)
		ts := s.riskTimes[agentID]
		keep := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(s.riskTimes, agentID)
			delete(s.riskCounts, agentID)
		} else {
			s.riskTimes[agentID] = keep
			s.riskCounts[agentID] = len(keep)
		}
	}
	if r := s.restrictions[agentID]; r != nil && !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt) {
		delete(s.restrictions, agentID)
	}
}

func NewShieldStore() *ShieldStore {
	return &ShieldStore{
		restrictions: make(map[string]*Restriction),
		riskCounts:   make(map[string]int),
		lastDecision: make(map[string]string),
		lastDecisionTime: make(map[string]time.Time),
		riskTimes:    make(map[string][]time.Time),
	}
}

func (s *ShieldStore) RecordDecision(agentID, decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastDecision[agentID] = decision
	s.lastDecisionTime[agentID] = time.Now()

	if decision == "deny" || decision == "escalate" {
		s.riskCounts[agentID]++
		s.riskTimes[agentID] = append(s.riskTimes[agentID], time.Now())
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(agentID)
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
	delete(s.riskTimes, agentID)
}

func (s *ShieldStore) GetRestriction(agentID string) *Restriction {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(agentID)
	if r, ok := s.restrictions[agentID]; ok {
		return r
	}
	return nil
}

func (s *ShieldStore) IsRestricted(agentID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(agentID)
	if r, ok := s.restrictions[agentID]; ok {
		return r.Restricted
	}
	return false
}

func (s *ShieldStore) GetAllRestricted() []*Restriction {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*Restriction
	for id := range s.restrictions {
		s.pruneLocked(id)
	}
	for _, r := range s.restrictions {
		result = append(result, r)
	}
	return result
}

func (s *ShieldStore) GetStats(agentID string) ShieldStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(agentID)
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
	s.pruneLocked(agentID)
	if count := s.riskCounts[agentID]; count >= threshold && s.restrictions[agentID] == nil {
		r := &Restriction{
			AgentID:    agentID,
			Restricted: true,
			Reason:     fmt.Sprintf("auto_restricted_after_%d_risk_events", count),
			Since:      time.Now(),
		}
		if s.autoTTL > 0 {
			r.ExpiresAt = r.Since.Add(s.autoTTL)
		}
		s.restrictions[agentID] = r
		return true
	}
	return false
}

func (s *ShieldStore) ShouldAutoRestrict(agentID string, threshold int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(agentID)
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

func (s *ShieldStore) Stats() (restricted, total int) {
	stats := s.GetAllStats()
	return stats.RestrictedCount, stats.TotalAgents
}
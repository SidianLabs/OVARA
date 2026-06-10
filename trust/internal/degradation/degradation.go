package degradation

import (
	"math"
	"sync"
)

type DegradationAgentState struct {
	Score      float64 `json:"score"`
	Streak     int     `json:"streak"`
	LastUnsafe bool    `json:"last_unsafe"`
}

type DegradationState struct {
	Agents       map[string]DegradationAgentState `json:"agents"`
	DecayRate    float64                          `json:"decay_rate"`
	RecoveryRate float64                          `json:"recovery_rate"`
	StreakAccel  float64                          `json:"streak_accel"`
	MinScore     float64                          `json:"min_score"`
	MaxScore     float64                          `json:"max_score"`
}

type agentScore struct {
	score      float64
	streak     int
	lastUnsafe bool
}

type DegradationModel struct {
	mu            sync.RWMutex
	agents        map[string]*agentScore
	decayRate     float64
	recoveryRate  float64
	streakAccel   float64
	minScore      float64
	maxScore      float64
}

func NewDegradationModel() *DegradationModel {
	return &DegradationModel{
		agents:       make(map[string]*agentScore),
		decayRate:    0.15,
		recoveryRate: 0.05,
		streakAccel:  1.5,
		minScore:     0.0,
		maxScore:     1.0,
	}
}

func (dm *DegradationModel) getOrCreate(agentID string) *agentScore {
	if s, ok := dm.agents[agentID]; ok {
		return s
	}
	s := &agentScore{score: 1.0}
	dm.agents[agentID] = s
	return s
}

func (dm *DegradationModel) RecordDecision(agentID string, decision string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	s := dm.getOrCreate(agentID)

	switch decision {
	case "deny", "escalate":
		if s.lastUnsafe {
			s.streak++
		} else {
			s.streak = 1
			s.lastUnsafe = true
		}
		accel := math.Pow(dm.streakAccel, float64(s.streak-1))
		decay := dm.decayRate * accel
		s.score -= s.score * decay
	case "allow":
		if !s.lastUnsafe {
			s.streak = 0
		} else {
			s.streak = 0
			s.lastUnsafe = false
		}
		gap := dm.maxScore - s.score
		s.score += gap * dm.recoveryRate
	}

	if s.score < dm.minScore {
		s.score = dm.minScore
	}
	if s.score > dm.maxScore {
		s.score = dm.maxScore
	}
}

func (dm *DegradationModel) GetScore(agentID string) float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	s, ok := dm.agents[agentID]
	if !ok {
		return 1.0
	}
	return s.score
}

func (dm *DegradationModel) GetLevel(agentID string) string {
	score := dm.GetScore(agentID)
	switch {
	case score >= 0.8:
		return "high"
	case score >= 0.5:
		return "medium"
	case score > 0.0:
		return "low"
	default:
		return "none"
	}
}

func (dm *DegradationModel) ExportState() DegradationState {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	state := DegradationState{
		Agents:       make(map[string]DegradationAgentState, len(dm.agents)),
		DecayRate:    dm.decayRate,
		RecoveryRate: dm.recoveryRate,
		StreakAccel:  dm.streakAccel,
		MinScore:     dm.minScore,
		MaxScore:     dm.maxScore,
	}

	for id, s := range dm.agents {
		state.Agents[id] = DegradationAgentState{
			Score:      s.score,
			Streak:     s.streak,
			LastUnsafe: s.lastUnsafe,
		}
	}

	return state
}

func (dm *DegradationModel) ImportState(state DegradationState) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.decayRate = state.DecayRate
	dm.recoveryRate = state.RecoveryRate
	dm.streakAccel = state.StreakAccel
	dm.minScore = state.MinScore
	dm.maxScore = state.MaxScore
	dm.agents = make(map[string]*agentScore, len(state.Agents))

	for id, as := range state.Agents {
		dm.agents[id] = &agentScore{
			score:      as.Score,
			streak:     as.Streak,
			lastUnsafe: as.LastUnsafe,
		}
	}
}

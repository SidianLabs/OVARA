package degradation

import (
	"math"
	"sync"
)

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

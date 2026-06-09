package trust

import (
	"math"
	"sync"
	"time"
)

// DegradationModel implements trust score degradation and recovery.
// Scores decay exponentially toward zero with repeated risky behavior and
// recover toward 1.0 with clean behavior following a configurable half-life.
//
// The model uses:
//   - Decay half-life: time for score to halve during degradation
//   - Recovery half-life: time for gap-to-1.0 to halve during recovery
//   - Accelerated degradation: each new risk event within the decay window
//     multiplies the current score by a penalty factor
type DegradationModel struct {
	mu sync.RWMutex

	// Per-agent state
	scores         map[string]float64
	lastRiskAt     map[string]time.Time
	lastCleanAt    map[string]time.Time
	riskStreak     map[string]int
	cleanStreak    map[string]int

	// Configuration
	decayHalfLife     time.Duration // score halves after this much time in degradation
	recoveryHalfLife  time.Duration // gap-to-1.0 halves after this much clean time
	penaltyFactor     float64       // multiplier per risk event (0 < penalty < 1)
	minScore          float64       // floor score
	maxScore          float64       // ceiling score
	initialScore      float64       // score for new agents
	streakThreshold   int           // consecutive risks before accelerated decay
}

// DegradationConfig holds the tunable parameters for the degradation model.
type DegradationConfig struct {
	DecayHalfLife    time.Duration
	RecoveryHalfLife  time.Duration
	PenaltyFactor    float64
	MinScore         float64
	MaxScore         float64
	InitialScore     float64
	StreakThreshold  int
}

// DefaultDegradationConfig returns sensible defaults.
func DefaultDegradationConfig() DegradationConfig {
	return DegradationConfig{
		DecayHalfLife:    30 * time.Minute,
		RecoveryHalfLife: 15 * time.Minute,
		PenaltyFactor:    0.85,
		MinScore:         0.1,
		MaxScore:         1.0,
		InitialScore:     0.85,
		StreakThreshold:  3,
	}
}

func NewDegradationModel(cfg DegradationConfig) *DegradationModel {
	if cfg.PenaltyFactor <= 0 {
		cfg.PenaltyFactor = 0.85
	}
	if cfg.MinScore <= 0 {
		cfg.MinScore = 0.1
	}
	if cfg.MaxScore <= 0 {
		cfg.MaxScore = 1.0
	}
	if cfg.InitialScore <= 0 {
		cfg.InitialScore = 0.85
	}
	if cfg.StreakThreshold <= 0 {
		cfg.StreakThreshold = 3
	}
	return &DegradationModel{
		scores:          make(map[string]float64),
		lastRiskAt:      make(map[string]time.Time),
		lastCleanAt:     make(map[string]time.Time),
		riskStreak:      make(map[string]int),
		cleanStreak:     make(map[string]int),
		decayHalfLife:   cfg.DecayHalfLife,
		recoveryHalfLife: cfg.RecoveryHalfLife,
		penaltyFactor:   cfg.PenaltyFactor,
		minScore:        cfg.MinScore,
		maxScore:        cfg.MaxScore,
		initialScore:    cfg.InitialScore,
		streakThreshold: cfg.StreakThreshold,
	}
}

// CurrentScore returns the current trust score for an agent, accounting for
// time-based recovery since the last check. New agents get the initial score.
func (dm *DegradationModel) CurrentScore(agentID string) float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	score, ok := dm.scores[agentID]
	if !ok {
		return dm.initialScore
	}

	// Apply time-based recovery from last clean action.
	if lastClean, ok := dm.lastCleanAt[agentID]; ok && !lastClean.IsZero() {
		elapsed := time.Since(lastClean)
		if elapsed > 0 && dm.recoveryHalfLife > 0 && score < dm.maxScore {
			gap := dm.maxScore - score
			// Recovery: gap halves every recoveryHalfLife
			halvings := float64(elapsed) / float64(dm.recoveryHalfLife)
			recovered := gap * (1 - math.Pow(0.5, halvings))
			score = math.Min(score+recovered, dm.maxScore)
		}
	}

	return score
}

// RecordRisk applies a penalty for a risky or anomalous action.
// Returns the new score and whether the agent is now in a risky state.
func (dm *DegradationModel) RecordRisk(agentID string) (float64, bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now().UTC()

	// Ensure agent exists
	if _, ok := dm.scores[agentID]; !ok {
		dm.scores[agentID] = dm.initialScore
	}

	// Apply time-based decay
	score := dm.scores[agentID]
	if lastRisk, ok := dm.lastRiskAt[agentID]; ok && !lastRisk.IsZero() {
		elapsed := now.Sub(lastRisk)
		if elapsed > 0 && dm.decayHalfLife > 0 {
			halvings := float64(elapsed) / float64(dm.decayHalfLife)
			score = score * math.Pow(0.5, halvings)
		}
	}

	// Apply streak penalty
	dm.riskStreak[agentID]++
	if dm.riskStreak[agentID] >= dm.streakThreshold {
		// Accelerated decay for persistent risky behavior
		score *= math.Pow(dm.penaltyFactor, float64(dm.riskStreak[agentID]))
	} else {
		score *= dm.penaltyFactor
	}

	score = math.Max(score, dm.minScore)
	dm.scores[agentID] = score
	dm.lastRiskAt[agentID] = now
	dm.cleanStreak[agentID] = 0

	return score, score < 0.5
}

// RecordClean applies recovery for a clean/safe action.
// Returns the new score.
func (dm *DegradationModel) RecordClean(agentID string) float64 {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now().UTC()

	score, ok := dm.scores[agentID]
	if !ok {
		score = dm.initialScore
	}

	dm.cleanStreak[agentID]++
	dm.riskStreak[agentID] = 0

	// Recovery: gap-to-1.0 reduces with each clean action in streak
	if score < dm.maxScore && dm.recoveryHalfLife > 0 {
		gap := dm.maxScore - score
		recoveryAmount := gap * 0.05 * float64(dm.cleanStreak[agentID])
		score = math.Min(score+recoveryAmount, dm.maxScore)
	}

	dm.scores[agentID] = score
	dm.lastCleanAt[agentID] = now

	return score
}

// GetState returns the full degradation state for an agent.
type DegradationState struct {
	Score        float64   `json:"score"`
	RiskStreak   int       `json:"risk_streak"`
	CleanStreak  int       `json:"clean_streak"`
	LastRiskAt   time.Time `json:"last_risk_at,omitempty"`
	LastCleanAt  time.Time `json:"last_clean_at,omitempty"`
	IsDegraded   bool      `json:"is_degraded"`
}

func (dm *DegradationModel) GetState(agentID string) DegradationState {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	score := dm.scores[agentID]
	if _, ok := dm.scores[agentID]; !ok {
		score = dm.initialScore
	}

	return DegradationState{
		Score:       score,
		RiskStreak:  dm.riskStreak[agentID],
		CleanStreak: dm.cleanStreak[agentID],
		LastRiskAt:  dm.lastRiskAt[agentID],
		LastCleanAt: dm.lastCleanAt[agentID],
		IsDegraded:  score < 0.5,
	}
}

// ResetScore resets an agent's score to the initial value.
func (dm *DegradationModel) ResetScore(agentID string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.scores[agentID] = dm.initialScore
	dm.riskStreak[agentID] = 0
	dm.cleanStreak[agentID] = 0
}

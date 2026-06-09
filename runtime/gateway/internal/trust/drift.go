package trust

import (
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// ActionWindow tracks an agent's action pattern within a sliding time window
// for drift detection. Actions outside the window are automatically evicted.
type ActionWindow struct {
	ActionType models.ActionType `json:"action_type"`
	Resource   string            `json:"resource"`
	Timestamp  time.Time         `json:"timestamp"`
	IsRisky    bool              `json:"is_risky"`
}

// DriftDetector tracks per-agent action history across sliding time windows
// to detect anomalous action patterns (e.g., sudden shift from read-only to
// destructive operations, or escalated frequency of risky actions).
type DriftDetector struct {
	mu            sync.RWMutex
	windows       map[string][]ActionWindow
	maxWindowSize int
	windowDur     time.Duration
	driftBaseline map[string]*AgentBaseline
}

// AgentBaseline records the established action pattern for an agent.
type AgentBaseline struct {
	AgentID          string                       `json:"agent_id"`
	PrimaryActions   map[models.ActionType]int     `json:"primary_actions"`
	TotalActions     int                           `json:"total_actions"`
	RiskyActionCount int                           `json:"risky_action_count"`
	EstablishedAt    time.Time                     `json:"established_at"`
	LastUpdatedAt    time.Time                     `json:"last_updated_at"`
}

// DriftResult captures the outcome of a drift check.
type DriftResult struct {
	Drifting    bool      `json:"drifting"`
	Reason      string    `json:"reason,omitempty"`
	DriftScore  float64   `json:"drift_score"`
	BaselineAge time.Duration `json:"baseline_age"`
}

func NewDriftDetector(maxWindowSize int, windowDur time.Duration) *DriftDetector {
	if maxWindowSize <= 0 {
		maxWindowSize = 100
	}
	if windowDur <= 0 {
		windowDur = 24 * time.Hour
	}
	return &DriftDetector{
		windows:       make(map[string][]ActionWindow),
		maxWindowSize: maxWindowSize,
		windowDur:     windowDur,
		driftBaseline: make(map[string]*AgentBaseline),
	}
}

// RecordAction records an action in the agent's sliding window and updates
// the baseline. This should be called on every evaluate check.
func (d *DriftDetector) RecordAction(agentID string, actionType models.ActionType, resource string, isRisky bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UTC()
	cutoff := now.Add(-d.windowDur)

	// Add new action
	window := d.windows[agentID]
	window = append(window, ActionWindow{ActionType: actionType, Resource: resource, Timestamp: now, IsRisky: isRisky})

	// Evict expired entries
	valid := window[:0]
	for _, w := range window {
		if w.Timestamp.After(cutoff) {
			valid = append(valid, w)
		}
	}
	// Enforce max size (keep most recent)
	if len(valid) > d.maxWindowSize {
		valid = valid[len(valid)-d.maxWindowSize:]
	}
	d.windows[agentID] = valid

	// Update baseline
	baseline, exists := d.driftBaseline[agentID]
	if !exists {
		baseline = &AgentBaseline{
			AgentID:        agentID,
			PrimaryActions: make(map[models.ActionType]int),
			EstablishedAt:  now,
		}
		d.driftBaseline[agentID] = baseline
	}

	baseline.TotalActions++
	baseline.PrimaryActions[actionType]++
	if isRisky {
		baseline.RiskyActionCount++
	}
	baseline.LastUpdatedAt = now
}

// CheckDrift evaluates whether the agent's recent actions deviate from
// their established baseline using a simple split within the sliding window:
// the older half is treated as baseline, the newer half as recent.
// Returns a DriftResult with score 0-1 where higher scores indicate
// stronger drift.
func (d *DriftDetector) CheckDrift(agentID string) *DriftResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	baseline, ok := d.driftBaseline[agentID]
	if !ok || baseline.TotalActions < 5 {
		return &DriftResult{Drifting: false, DriftScore: 0}
	}

	window := d.windows[agentID]
	if len(window) < 6 {
		return &DriftResult{Drifting: false, DriftScore: 0, BaselineAge: time.Since(baseline.EstablishedAt)}
	}

	// Split window: first half is baseline, second half is recent.
	mid := len(window) / 2
	baselineHalf := window[:mid]
	recentHalf := window[mid:]

	baselineActions := make(map[models.ActionType]int)
	totalBaseline := len(baselineHalf)
	for _, w := range baselineHalf {
		baselineActions[w.ActionType]++
	}

	recentActions := make(map[models.ActionType]int)
	totalRecent := len(recentHalf)
	recentRisky := 0
	for _, w := range recentHalf {
		recentActions[w.ActionType]++
		if w.IsRisky {
			recentRisky++
		}
	}

	if totalBaseline < 3 || totalRecent < 1 {
		return &DriftResult{Drifting: false, DriftScore: 0, BaselineAge: time.Since(baseline.EstablishedAt)}
	}

	// Drift: fraction of recent actions whose action type is novel vs. baseline
	novelCount := 0
	for at, count := range recentActions {
		baselineCount, exists := baselineActions[at]
		if !exists || float64(baselineCount)/float64(totalBaseline) < 0.05 {
			novelCount += count
		}
	}

	var driftScore float64
	if totalRecent > 0 {
		driftScore = float64(novelCount) / float64(totalRecent)
	}
	if driftScore > 1.0 {
		driftScore = 1.0
	}

	// Risky action density spike
	riskyDensity := float64(recentRisky) / float64(totalRecent)
	if totalRecent > 3 && riskyDensity > 0.3 {
		driftScore += 0.2
		if driftScore > 1.0 {
			driftScore = 1.0
		}
	}

	result := &DriftResult{
		DriftScore:  driftScore,
		BaselineAge: time.Since(baseline.EstablishedAt),
	}

	if driftScore > 0.5 {
		result.Drifting = true
		result.Reason = "significant deviation from established action baseline"
	} else if driftScore > 0.25 {
		result.Drifting = true
		result.Reason = "moderate deviation from action baseline"
	}

	return result
}

// GetBaseline returns the current baseline for an agent.
func (d *DriftDetector) GetBaseline(agentID string) *AgentBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.driftBaseline[agentID]
}

// ClearBaseline resets the baseline for an agent (e.g., after containment/remediation).
func (d *DriftDetector) ClearBaseline(agentID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.driftBaseline, agentID)
	delete(d.windows, agentID)
}

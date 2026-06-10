package drift

import "sync"

type DriftResult struct {
	Drifting   bool    `json:"drifting"`
	Confidence float64 `json:"confidence"`
	Window     int     `json:"window"`
}

type actionEntry struct {
	isRisky bool
}

type agentState struct {
	actions []actionEntry
	head    int
	size    int
	count   int
}

type DriftDetector struct {
	mu        sync.RWMutex
	window    int
	threshold float64
	agents    map[string]*agentState
}

func NewDriftDetector(window int, threshold float64) *DriftDetector {
	if window < 1 {
		window = 10
	}
	if threshold < 0 || threshold > 1 {
		threshold = 0.5
	}
	return &DriftDetector{
		window:    window,
		threshold: threshold,
		agents:    make(map[string]*agentState),
	}
}

func (d *DriftDetector) getOrCreate(agentID string) *agentState {
	if s, ok := d.agents[agentID]; ok {
		return s
	}
	s := &agentState{
		actions: make([]actionEntry, d.window),
	}
	d.agents[agentID] = s
	return s
}

func (d *DriftDetector) RecordAction(agentID string, actionType string, isRisky bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	s := d.getOrCreate(agentID)
	s.actions[s.head] = actionEntry{isRisky: isRisky}
	s.head = (s.head + 1) % d.window
	if s.count < d.window {
		s.count++
	}
}

func (d *DriftDetector) CheckDrift(agentID string) DriftResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	s, ok := d.agents[agentID]
	if !ok || s.count == 0 {
		return DriftResult{Drifting: false, Confidence: 0, Window: d.window}
	}

	riskyCount := 0
	start := 0
	if s.count == d.window {
		start = s.head
	}
	for i := 0; i < s.count; i++ {
		idx := (start + i) % d.window
		if s.actions[idx].isRisky {
			riskyCount++
		}
	}

	ratio := float64(riskyCount) / float64(s.count)
	drifting := ratio >= d.threshold

	return DriftResult{
		Drifting:   drifting,
		Confidence: ratio,
		Window:     s.count,
	}
}

package drift

import "sync"

type DriftWindowEntry struct {
	IsRisky  bool   `json:"is_risky"`
	Action   string `json:"action"`
	Timestamp int64  `json:"timestamp"`
}

type DriftState struct {
	Window    int                            `json:"window"`
	Threshold float64                        `json:"threshold"`
	Agents    map[string]DriftAgentState     `json:"agents"`
}

type DriftAgentState struct {
	Actions []DriftWindowEntry `json:"actions"`
	Head    int                `json:"head"`
	Size    int                `json:"size"`
	Count   int                `json:"count"`
}

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

func (d *DriftDetector) ExportState() DriftState {
	d.mu.RLock()
	defer d.mu.RUnlock()

	state := DriftState{
		Window:    d.window,
		Threshold: d.threshold,
		Agents:    make(map[string]DriftAgentState, len(d.agents)),
	}

	for id, s := range d.agents {
		actions := make([]DriftWindowEntry, len(s.actions))
		for i, a := range s.actions {
			actions[i] = DriftWindowEntry{
				IsRisky:  a.isRisky,
				Action:   "",
				Timestamp: 0,
			}
		}
		state.Agents[id] = DriftAgentState{
			Actions: actions,
			Head:    s.head,
			Size:    s.size,
			Count:   s.count,
		}
	}

	return state
}

func (d *DriftDetector) ImportState(state DriftState) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.window = state.Window
	d.threshold = state.Threshold
	d.agents = make(map[string]*agentState, len(state.Agents))

	for id, as := range state.Agents {
		actions := make([]actionEntry, len(as.Actions))
		for i, a := range as.Actions {
			actions[i] = actionEntry{isRisky: a.IsRisky}
		}
		d.agents[id] = &agentState{
			actions: actions,
			head:    as.Head,
			size:    as.Size,
			count:   as.Count,
		}
	}
}

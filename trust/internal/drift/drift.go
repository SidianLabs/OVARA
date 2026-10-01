package drift

import (
	"sync"
	"time"
)

type DriftWindowEntry struct {
	IsRisky   bool   `json:"is_risky"`
	Action    string `json:"action"`
	Timestamp int64  `json:"timestamp"`
}

type DriftState struct {
	Window    int                        `json:"window"`
	Threshold float64                    `json:"threshold"`
	Agents    map[string]DriftAgentState `json:"agents"`
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
	isRisky   bool
	action    string
	timestamp int64
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
	s.actions[s.head] = actionEntry{isRisky: isRisky, action: actionType, timestamp: time.Now().UTC().UnixNano()}
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
				IsRisky:   a.isRisky,
				Action:    a.action,
				Timestamp: a.timestamp,
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

	// Clamp to the same bounds as NewDriftDetector: an imported Window of 0
	// would cause a division-by-zero panic in RecordAction.
	if state.Window < 1 {
		d.window = 10
	} else {
		d.window = state.Window
	}
	if state.Threshold < 0 || state.Threshold > 1 {
		d.threshold = 0.5
	} else {
		d.threshold = state.Threshold
	}
	d.agents = make(map[string]*agentState, len(state.Agents))

	for id, as := range state.Agents {
		// The ring buffer must be at least window-sized or RecordAction will
		// index out of bounds.
		n := len(as.Actions)
		if n < d.window {
			n = d.window
		}
		actions := make([]actionEntry, n)
		for i, a := range as.Actions {
			if i >= n {
				break
			}
			actions[i] = actionEntry{isRisky: a.IsRisky, action: a.Action, timestamp: a.Timestamp}
		}
		head := as.Head
		if head < 0 || head >= d.window {
			head = 0
		}
		count := as.Count
		if count < 0 || count > d.window {
			count = d.window
		}
		d.agents[id] = &agentState{
			actions: actions,
			head:    head,
			size:    as.Size,
			count:   count,
		}
	}
}

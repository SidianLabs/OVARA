package chain_detection

import (
	"sort"
	"sync"
	"time"
)

type Suspicion struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ChainRecordExport struct {
	ChainHash string `json:"chain_hash"`
	Depth     int    `json:"depth"`
	Timestamp int64  `json:"timestamp"`
}

type ChainState struct {
	Agents         map[string][]ChainRecordExport `json:"agents"`
	MaxDepth       int                             `json:"max_depth"`
	RapidWindowSec int64                           `json:"rapid_window_sec"`
	RapidThreshold int                             `json:"rapid_threshold"`
}

type chainRecord struct {
	chainHash string
	depth     int
	timestamp time.Time
}

type ChainDetector struct {
	mu              sync.RWMutex
	chains          map[string][]chainRecord
	maxDepth        int
	rapidWindowSec  int64
	rapidThreshold  int
}

func NewChainDetector() *ChainDetector {
	return &ChainDetector{
		chains:         make(map[string][]chainRecord),
		maxDepth:       5,
		rapidWindowSec: 60,
		rapidThreshold: 3,
	}
}

func (cd *ChainDetector) RecordChain(agentID string, chainHash string, depth int) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	cd.chains[agentID] = append(cd.chains[agentID], chainRecord{
		chainHash: chainHash,
		depth:     depth,
		timestamp: time.Now().UTC(),
	})
}

func (cd *ChainDetector) DetectSuspiciousPatterns(agentID string) []Suspicion {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	var suspicions []Suspicion
	records, ok := cd.chains[agentID]
	if !ok || len(records) == 0 {
		return suspicions
	}

	for _, r := range records {
		if r.depth > cd.maxDepth {
			suspicions = append(suspicions, Suspicion{
				Type:        "excessive_depth",
				Severity:    "high",
				Description: "delegation chain depth " + itoa(r.depth) + " exceeds maximum " + itoa(cd.maxDepth),
			})
		}
		if r.depth == 0 && len(r.chainHash) > 0 {
			suspicions = append(suspicions, Suspicion{
				Type:        "self_delegation",
				Severity:    "critical",
				Description: "agent delegated to itself (chain hash: " + r.chainHash + ")",
			})
		}
	}

	now := time.Now().UTC()
	recentCount := 0
	for _, r := range records {
		if now.Sub(r.timestamp).Seconds() <= float64(cd.rapidWindowSec) {
			recentCount++
		}
	}
	if recentCount >= cd.rapidThreshold {
		suspicions = append(suspicions, Suspicion{
			Type:        "rapid_redelegation",
			Severity:    "medium",
			Description: itoa(recentCount) + " chains recorded within " + itoa64(cd.rapidWindowSec) + "s window",
		})
	}

	sort.Slice(suspicions, func(i, j int) bool {
		return suspicions[i].Severity > suspicions[j].Severity
	})

	return suspicions
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func itoa64(n int64) string {
	return itoa(int(n))
}

func (cd *ChainDetector) ExportState() ChainState {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	state := ChainState{
		Agents:         make(map[string][]ChainRecordExport, len(cd.chains)),
		MaxDepth:       cd.maxDepth,
		RapidWindowSec: cd.rapidWindowSec,
		RapidThreshold: cd.rapidThreshold,
	}

	for id, records := range cd.chains {
		exports := make([]ChainRecordExport, len(records))
		for i, r := range records {
			exports[i] = ChainRecordExport{
				ChainHash: r.chainHash,
				Depth:     r.depth,
				Timestamp: r.timestamp.UnixNano(),
			}
		}
		state.Agents[id] = exports
	}

	return state
}

func (cd *ChainDetector) ImportState(state ChainState) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	cd.maxDepth = state.MaxDepth
	cd.rapidWindowSec = state.RapidWindowSec
	cd.rapidThreshold = state.RapidThreshold
	cd.chains = make(map[string][]chainRecord, len(state.Agents))

	for id, records := range state.Agents {
		imported := make([]chainRecord, len(records))
		for i, r := range records {
			imported[i] = chainRecord{
				chainHash: r.ChainHash,
				depth:     r.Depth,
				timestamp: time.Unix(0, r.Timestamp).UTC(),
			}
		}
		cd.chains[id] = imported
	}
}

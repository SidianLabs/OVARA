package trust

import (
	"strconv"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// ChainSuspicion captures a detected suspicious delegation pattern.
type ChainSuspicion struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// ChainDetector analyzes delegation patterns for suspicious behavior:
// - Same issuer appearing multiple times (potential authority loop)
// - Excessive delegation depth
// - Rapid re-delegation (frequency-based)
// - Self-delegation (issuer == subject)
type ChainDetector struct {
	mu              sync.RWMutex
	recentChains    map[string][]recentChainEntry // per-agent
	maxEntries      int
	trackingWindow  time.Duration
	maxDepth        int
}

type recentChainEntry struct {
	Depth     int
	Issuers   []string
	Subjects  []string
	Timestamp time.Time
}

func NewChainDetector(maxEntries int, trackingWindow time.Duration, maxDepth int) *ChainDetector {
	if maxEntries <= 0 {
		maxEntries = 50
	}
	if trackingWindow <= 0 {
		trackingWindow = 1 * time.Hour
	}
	if maxDepth <= 0 {
		maxDepth = 5
	}
	return &ChainDetector{
		recentChains:   make(map[string][]recentChainEntry),
		maxEntries:     maxEntries,
		trackingWindow: trackingWindow,
		maxDepth:       maxDepth,
	}
}

// RecordChain records a delegation chain for pattern analysis.
func (cd *ChainDetector) RecordChain(agentID string, chain *models.DelegationChain) {
	if chain == nil {
		return
	}

	cd.mu.Lock()
	defer cd.mu.Unlock()

	issuers := make([]string, len(chain.Authorities))
	subjects := make([]string, len(chain.Authorities))
	for i, a := range chain.Authorities {
		issuers[i] = a.Issuer
		subjects[i] = a.SubjectID
	}

	entry := recentChainEntry{
		Depth:     chain.Depth,
		Issuers:   issuers,
		Subjects:  subjects,
		Timestamp: time.Now().UTC(),
	}

	entries := cd.recentChains[agentID]

	// Evict old entries
	cutoff := time.Now().UTC().Add(-cd.trackingWindow)
	valid := entries[:0]
	for _, e := range entries {
		if e.Timestamp.After(cutoff) {
			valid = append(valid, e)
		}
	}
	valid = append(valid, entry)
	if len(valid) > cd.maxEntries {
		valid = valid[len(valid)-cd.maxEntries:]
	}
	cd.recentChains[agentID] = valid
}

// DetectSuspiciousPatterns analyzes recent chains for an agent and returns
// any suspicious patterns detected.
func (cd *ChainDetector) DetectSuspiciousPatterns(agentID string) []ChainSuspicion {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	entries := cd.recentChains[agentID]
	if len(entries) == 0 {
		return nil
	}

	var suspicions []ChainSuspicion

	// Check latest entry for immediate issues
	latest := entries[len(entries)-1]

	// Excessive depth
	if latest.Depth > cd.maxDepth {
		suspicions = append(suspicions, ChainSuspicion{
			Code:        "excessive_delegation_depth",
			Description: "delegation chain depth exceeds maximum",
			Severity:    "medium",
		})
	}

	// Self-delegation detection
	for i := 0; i < len(latest.Issuers); i++ {
		if i < len(latest.Subjects) && latest.Issuers[i] == latest.Subjects[i] {
			suspicions = append(suspicions, ChainSuspicion{
				Code:        "self_delegation",
				Description: "authority delegates to itself at position " + strconv.Itoa(i),
				Severity:    "high",
			})
			break
		}
	}

	// Same-issuer repetition across recent chains
	issuerFreq := make(map[string]int)
	for _, e := range entries {
		for _, issuer := range e.Issuers {
			issuerFreq[issuer]++
		}
	}
	for issuer, count := range issuerFreq {
		if count >= 5 && len(entries) >= 3 {
			suspicions = append(suspicions, ChainSuspicion{
				Code:        "issuer_concentration",
				Description: "issuer " + issuer + " appears in " + strconv.Itoa(count) + " recent delegations",
				Severity:    "low",
			})
		}
	}

	// Rapid re-delegation (multiple chains in short time)
	if len(entries) >= 5 {
		timeSinceFirst := latest.Timestamp.Sub(entries[0].Timestamp)
		if timeSinceFirst < 5*time.Minute {
			suspicions = append(suspicions, ChainSuspicion{
				Code:        "rapid_redelegation",
				Description: strconv.Itoa(len(entries)) + " delegations in " + timeSinceFirst.String(),
				Severity:    "medium",
			})
		}
	}

	return suspicions
}

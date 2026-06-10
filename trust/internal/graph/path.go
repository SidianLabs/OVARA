package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type TrustPath struct {
	Domains    []TrustDomain `json:"domains"`
	TrustScore float64       `json:"trust_score"`
	Depth      int           `json:"depth"`
}

func (tp *TrustPath) IsDirect() bool {
	return tp.Depth == 1
}

func (tp *TrustPath) Hash() string {
	payload := fmt.Sprintf("%d|", tp.Depth)
	for _, d := range tp.Domains {
		payload += string(d) + "|"
	}
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// ComputeTrustPath finds the optimal trust path from source to target using DFS.
func (tg *TrustGraph) ComputeTrustPath(source, target TrustDomain) (*TrustPath, error) {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	if err := tg.requireNode(source); err != nil {
		return nil, err
	}
	if err := tg.requireNode(target); err != nil {
		return nil, err
	}

	if source == target {
		return &TrustPath{
			Domains:    []TrustDomain{source},
			TrustScore: 1.0,
			Depth:      0,
		}, nil
	}

	visited := make(map[TrustDomain]bool)

	var bestScore float64 = -1
	var bestChain []TrustDomain
	var bestDepth int

	var dfs func(current TrustDomain, score float64, depth int, chain []TrustDomain)
	dfs = func(current TrustDomain, score float64, depth int, chain []TrustDomain) {
		if depth > 10 {
			return
		}
		if current == target {
			cfgScore := float64(1.0) / float64(depth+1)
			composite := score*0.7 + cfgScore*0.3
			if composite > bestScore {
				bestScore = composite
				bestChain = make([]TrustDomain, len(chain))
				copy(bestChain, chain)
				bestDepth = depth
			}
			return
		}

		visited[current] = true
		defer delete(visited, current)

		if edges, ok := tg.edges[current]; ok {
			for next, rel := range edges {
				if visited[next] || !rel.Active {
					continue
				}
				newScore := score * rel.TrustLevel
				newChain := make([]TrustDomain, len(chain)+1)
				copy(newChain, chain)
				newChain[len(chain)] = next
				dfs(next, newScore, depth+1, newChain)
			}
		}
	}

	dfs(source, 1.0, 0, []TrustDomain{source})

	if bestScore < 0 {
		return nil, fmt.Errorf("no trust path between %s and %s", source, target)
	}

	return &TrustPath{
		Domains:    bestChain,
		TrustScore: bestScore,
		Depth:      bestDepth,
	}, nil
}

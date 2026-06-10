package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

type TrustDomain string

type TrustRelationship struct {
	SourceOrg      TrustDomain `json:"source_org"`
	TargetOrg      TrustDomain `json:"target_org"`
	TrustLevel     float64     `json:"trust_level"`
	FederatedSince time.Time   `json:"federated_since"`
	LastUpdated    time.Time   `json:"last_updated"`
	Active         bool        `json:"active"`
	PublicKeys     [][]byte    `json:"public_keys,omitempty"`
}

type TrustGraph struct {
	mu          sync.RWMutex
	nodes       map[TrustDomain]*OrganizationNode
	edges       map[TrustDomain]map[TrustDomain]*TrustRelationship
}

type OrganizationNode struct {
	Domain      TrustDomain       `json:"domain"`
	Name        string            `json:"name"`
	PublicKeys  [][]byte          `json:"public_keys"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	JoinedAt    time.Time         `json:"joined_at"`
	Active      bool              `json:"active"`
}

func NewTrustGraph() *TrustGraph {
	return &TrustGraph{
		nodes: make(map[TrustDomain]*OrganizationNode),
		edges: make(map[TrustDomain]map[TrustDomain]*TrustRelationship),
	}
}

func (tg *TrustGraph) AddOrganization(domain TrustDomain, name string, publicKeys [][]byte) error {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	if _, exists := tg.nodes[domain]; exists {
		return fmt.Errorf("organization %s already exists", domain)
	}

	tg.nodes[domain] = &OrganizationNode{
		Domain:     domain,
		Name:       name,
		PublicKeys: publicKeys,
		JoinedAt:   time.Now().UTC(),
		Active:     true,
	}
	return nil
}

func (tg *TrustGraph) RemoveOrganization(domain TrustDomain) error {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	if _, exists := tg.nodes[domain]; !exists {
		return fmt.Errorf("organization %s not found", domain)
	}

	delete(tg.nodes, domain)
	delete(tg.edges, domain)
	for _, targets := range tg.edges {
		delete(targets, domain)
	}
	return nil
}

func (tg *TrustGraph) Federate(source, target TrustDomain, trustLevel float64, targetPublicKeys [][]byte) error {
	if trustLevel < 0 || trustLevel > 1 {
		return fmt.Errorf("trust level must be between 0 and 1")
	}

	tg.mu.Lock()
	defer tg.mu.Unlock()

	if err := tg.requireNode(source); err != nil {
		return err
	}
	if err := tg.requireNode(target); err != nil {
		return err
	}

	now := time.Now().UTC()
	targetNode := tg.nodes[target]
	for _, key := range targetPublicKeys {
		targetNode.PublicKeys = append(targetNode.PublicKeys, key)
	}

	if tg.edges[source] == nil {
		tg.edges[source] = make(map[TrustDomain]*TrustRelationship)
	}

	if existing, ok := tg.edges[source][target]; ok {
		existing.TrustLevel = trustLevel
		existing.LastUpdated = now
		existing.Active = true
		existing.PublicKeys = append(existing.PublicKeys, targetPublicKeys...)
	} else {
		tg.edges[source][target] = &TrustRelationship{
			SourceOrg:      source,
			TargetOrg:      target,
			TrustLevel:     trustLevel,
			FederatedSince: now,
			LastUpdated:    now,
			Active:         true,
			PublicKeys:     targetPublicKeys,
		}
	}
	return nil
}

func (tg *TrustGraph) RevokeFederation(source, target TrustDomain) error {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	if err := tg.requireNode(source); err != nil {
		return err
	}
	if err := tg.requireNode(target); err != nil {
		return err
	}

	if tg.edges[source] == nil || tg.edges[source][target] == nil {
		return fmt.Errorf("no federation between %s and %s", source, target)
	}

	tg.edges[source][target].Active = false
	tg.edges[source][target].LastUpdated = time.Now().UTC()
	return nil
}

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
	type pathState struct {
		domain     TrustDomain
		score      float64
		depth      int
		chain      []TrustDomain
	}

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
			composite := score * 0.7 + cfgScore * 0.3
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

type TrustPath struct {
	Domains    []TrustDomain `json:"domains"`
	TrustScore float64       `json:"trust_score"`
	Depth      int           `json:"depth"`
}

func (tp *TrustPath) IsDirect() bool {
	return tp.Depth == 1
}

func (tg *TrustGraph) GetNeighbors(domain TrustDomain) []TrustRelationship {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	var rels []TrustRelationship
	if edges, ok := tg.edges[domain]; ok {
		for _, rel := range edges {
			rels = append(rels, *rel)
		}
	}
	sort.Slice(rels, func(i, j int) bool {
		return rels[i].TrustLevel > rels[j].TrustLevel
	})
	return rels
}

func (tg *TrustGraph) GetAllOrganizations() []OrganizationNode {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	var orgs []OrganizationNode
	for _, node := range tg.nodes {
		orgs = append(orgs, *node)
	}
	sort.Slice(orgs, func(i, j int) bool {
		return orgs[i].Domain < orgs[j].Domain
	})
	return orgs
}

func (tg *TrustGraph) Snapshot() map[string]interface{} {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	nodes := make([]OrganizationNode, 0, len(tg.nodes))
	for _, n := range tg.nodes {
		nodes = append(nodes, *n)
	}

	edges := make([]TrustRelationship, 0)
	for _, targets := range tg.edges {
		for _, rel := range targets {
			edges = append(edges, *rel)
		}
	}

	return map[string]interface{}{
		"organizations": nodes,
		"relationships": edges,
		"node_count":    len(tg.nodes),
		"edge_count":    len(edges),
	}
}

func (tg *TrustGraph) requireNode(domain TrustDomain) error {
	if _, exists := tg.nodes[domain]; !exists {
		return fmt.Errorf("organization %s not found", domain)
	}
	return nil
}

func (tp *TrustPath) Hash() string {
	payload := fmt.Sprintf("%d|", tp.Depth)
	for _, d := range tp.Domains {
		payload += string(d) + "|"
	}
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

type FederatedIdentity struct {
	IdentityDigest string    `json:"identity_digest"`
	Domain         string    `json:"domain"`
	SigningKey     []byte    `json:"signing_key,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type CrossOrgReceipt struct {
	ReceiptID      string    `json:"receipt_id"`
	DecisionID     string    `json:"decision_id"`
	IssuingGateway string    `json:"issuing_gateway"`
	IssuingOrg     string    `json:"issuing_org"`
	ActionType     string    `json:"action_type"`
	Resource       string    `json:"resource"`
	Decision       string    `json:"decision"`
	AgentIdentity  string    `json:"agent_identity"`
	LeaseDigest    string    `json:"lease_digest,omitempty"`
	TrustScore     float64   `json:"trust_score"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      []byte    `json:"signature"`
}

func (r *CrossOrgReceipt) Verify(publicKey []byte) bool {
	if len(r.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	payload := r.Digest()
	return ed25519.Verify(publicKey, []byte(payload), r.Signature)
}

func (r *CrossOrgReceipt) Digest() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%d",
		r.ReceiptID, r.DecisionID, r.IssuingGateway, r.IssuingOrg,
		r.ActionType, r.Resource, r.Decision, r.AgentIdentity,
		r.TrustScore, r.Timestamp.Unix(),
	)
	return payload
}

func SignCrossOrgReceipt(receipt *CrossOrgReceipt, signingKey ed25519.PrivateKey) error {
	payload := receipt.Digest()
	sig := ed25519.Sign(signingKey, []byte(payload))
	receipt.Signature = sig
	return nil
}

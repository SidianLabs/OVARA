package graph

import (
	"crypto/ed25519"
	"crypto/subtle"
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
	mu    sync.RWMutex
	nodes map[TrustDomain]*OrganizationNode
	edges map[TrustDomain]map[TrustDomain]*TrustRelationship
}

type OrganizationNode struct {
	Domain     TrustDomain       `json:"domain"`
	Name       string            `json:"name"`
	PublicKeys [][]byte          `json:"public_keys"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	JoinedAt   time.Time         `json:"joined_at"`
	Active     bool              `json:"active"`
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
		PublicKeys: cloneKeys(publicKeys),
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
	// Federation may only reference keys already registered to the target via
	// /v1/domains. Accepting arbitrary keys here would let any registered org
	// inject attacker-controlled keys into a victim domain and verify
	// receipts as the victim.
	for _, key := range targetPublicKeys {
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("target public key must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
		}
		if !containsKey(targetNode.PublicKeys, key) {
			return fmt.Errorf("target public key %x… is not registered for %s", key[:4], target)
		}
	}

	if tg.edges[source] == nil {
		tg.edges[source] = make(map[TrustDomain]*TrustRelationship)
	}

	if existing, ok := tg.edges[source][target]; ok {
		existing.TrustLevel = trustLevel
		existing.LastUpdated = now
		existing.Active = true
		for _, key := range targetPublicKeys {
			if !containsKey(existing.PublicKeys, key) {
				existing.PublicKeys = append(existing.PublicKeys, key)
			}
		}
	} else {
		tg.edges[source][target] = &TrustRelationship{
			SourceOrg:      source,
			TargetOrg:      target,
			TrustLevel:     trustLevel,
			FederatedSince: now,
			LastUpdated:    now,
			Active:         true,
			PublicKeys:     cloneKeys(targetPublicKeys),
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

func (tg *TrustGraph) GetNeighbors(domain TrustDomain) []TrustRelationship {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	var rels []TrustRelationship
	if edges, ok := tg.edges[domain]; ok {
		for _, rel := range edges {
			rels = append(rels, *cloneRelationship(rel))
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
		orgs = append(orgs, *cloneNode(node))
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
		nodes = append(nodes, *cloneNode(n))
	}

	edges := make([]TrustRelationship, 0)
	for _, targets := range tg.edges {
		for _, rel := range targets {
			edges = append(edges, *cloneRelationship(rel))
		}
	}

	return map[string]interface{}{
		"organizations": nodes,
		"relationships": edges,
		"node_count":    len(tg.nodes),
		"edge_count":    len(edges),
	}
}

// containsKey reports whether key is already present in keys.
func containsKey(keys [][]byte, key []byte) bool {
	for _, k := range keys {
		if subtle.ConstantTimeCompare(k, key) == 1 {
			return true
		}
	}
	return false
}

func (tg *TrustGraph) requireNode(domain TrustDomain) error {
	if _, exists := tg.nodes[domain]; !exists {
		return fmt.Errorf("organization %s not found", domain)
	}
	return nil
}

func cloneKeys(keys [][]byte) [][]byte {
	if keys == nil {
		return nil
	}
	out := make([][]byte, len(keys))
	for i, k := range keys {
		kc := make([]byte, len(k))
		copy(kc, k)
		out[i] = kc
	}
	return out
}

func cloneMetadata(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneNode(n *OrganizationNode) *OrganizationNode {
	if n == nil {
		return nil
	}
	cp := *n
	cp.PublicKeys = cloneKeys(n.PublicKeys)
	cp.Metadata = cloneMetadata(n.Metadata)
	return &cp
}

func cloneRelationship(r *TrustRelationship) *TrustRelationship {
	if r == nil {
		return nil
	}
	cp := *r
	cp.PublicKeys = cloneKeys(r.PublicKeys)
	return &cp
}

// GetNode returns a copy of an organization node by domain. The returned
// node is a deep copy — mutating it does not affect graph state.
func (tg *TrustGraph) GetNode(domain TrustDomain) (*OrganizationNode, bool) {
	tg.mu.RLock()
	defer tg.mu.RUnlock()
	node, ok := tg.nodes[domain]
	if !ok {
		return nil, false
	}
	return cloneNode(node), true
}

// GetRelationship returns a copy of the trust relationship between source
// and target.
func (tg *TrustGraph) GetRelationship(source, target TrustDomain) (*TrustRelationship, bool) {
	tg.mu.RLock()
	defer tg.mu.RUnlock()
	if targets, ok := tg.edges[source]; ok {
		if rel, ok := targets[target]; ok {
			return cloneRelationship(rel), true
		}
	}
	return nil, false
}

// GraphSnapshot is a serializable representation of the entire trust graph.
// Used for persistence and cross-instance sync.
type GraphSnapshot struct {
	Version       string              `json:"version"`
	Nodes         []OrganizationNode  `json:"nodes"`
	Relationships []TrustRelationship `json:"relationships"`
}

// SnapshotV2 returns a versioned, JSON-serializable snapshot of the graph.
func (tg *TrustGraph) SnapshotV2() GraphSnapshot {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	nodes := make([]OrganizationNode, 0, len(tg.nodes))
	for _, n := range tg.nodes {
		nodes = append(nodes, *cloneNode(n))
	}

	edges := make([]TrustRelationship, 0)
	for _, targets := range tg.edges {
		for _, rel := range targets {
			edges = append(edges, *cloneRelationship(rel))
		}
	}

	return GraphSnapshot{
		Version:       "v1",
		Nodes:         nodes,
		Relationships: edges,
	}
}

// RestoreFromSnapshot replaces the current graph state with the provided snapshot.
// Used for loading persisted state on startup.
func (tg *TrustGraph) RestoreFromSnapshot(snap GraphSnapshot) error {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	tg.nodes = make(map[TrustDomain]*OrganizationNode)
	tg.edges = make(map[TrustDomain]map[TrustDomain]*TrustRelationship)

	for _, n := range snap.Nodes {
		node := n
		tg.nodes[n.Domain] = &node
	}

	for _, r := range snap.Relationships {
		rel := r
		if tg.edges[r.SourceOrg] == nil {
			tg.edges[r.SourceOrg] = make(map[TrustDomain]*TrustRelationship)
		}
		tg.edges[r.SourceOrg][r.TargetOrg] = &rel
	}

	return nil
}

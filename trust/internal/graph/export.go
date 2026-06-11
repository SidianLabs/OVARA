package graph

import (
	"encoding/json"
	"fmt"
)

type ExportedTrustState struct {
	Version       string            `json:"version"`
	ExportedAt    string            `json:"exported_at"`
	Organizations []OrganizationNode `json:"organizations"`
	Relationships []TrustRelationship `json:"relationships"`
}

func (tg *TrustGraph) Export() (*ExportedTrustState, error) {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	orgs := make([]OrganizationNode, 0, len(tg.nodes))
	for _, n := range tg.nodes {
		orgs = append(orgs, *n)
	}

	edges := make([]TrustRelationship, 0)
	for _, targets := range tg.edges {
		for _, rel := range targets {
			edges = append(edges, *rel)
		}
	}

	return &ExportedTrustState{
		Version:       "1.0",
		Organizations: orgs,
		Relationships: edges,
	}, nil
}

func (tg *TrustGraph) ExportJSON() ([]byte, error) {
	state, err := tg.Export()
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func (tg *TrustGraph) Import(state *ExportedTrustState) error {
	if state == nil {
		return fmt.Errorf("nil trust state")
	}
	if state.Version == "" {
		return fmt.Errorf("missing version in trust state")
	}

	tg.mu.Lock()
	defer tg.mu.Unlock()

	tg.nodes = make(map[TrustDomain]*OrganizationNode)
	tg.edges = make(map[TrustDomain]map[TrustDomain]*TrustRelationship)

	for _, org := range state.Organizations {
		node := org
		tg.nodes[org.Domain] = &node
	}

	for _, rel := range state.Relationships {
		relationship := rel
		if tg.edges[rel.SourceOrg] == nil {
			tg.edges[rel.SourceOrg] = make(map[TrustDomain]*TrustRelationship)
		}
		tg.edges[rel.SourceOrg][rel.TargetOrg] = &relationship
	}

	return nil
}

func (tg *TrustGraph) ImportJSON(data []byte) error {
	var state ExportedTrustState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	return tg.Import(&state)
}

func (tg *TrustGraph) Merge(other *TrustGraph) error {
	otherState, err := other.Export()
	if err != nil {
		return err
	}

	tg.mu.Lock()
	defer tg.mu.Unlock()

	for _, org := range otherState.Organizations {
		if _, exists := tg.nodes[org.Domain]; !exists {
			node := org
			tg.nodes[org.Domain] = &node
		}
	}

	for _, rel := range otherState.Relationships {
		if tg.edges[rel.SourceOrg] == nil {
			tg.edges[rel.SourceOrg] = make(map[TrustDomain]*TrustRelationship)
		}
		existing, ok := tg.edges[rel.SourceOrg][rel.TargetOrg]
		if !ok || rel.TrustLevel > existing.TrustLevel {
			relationship := rel
			tg.edges[rel.SourceOrg][rel.TargetOrg] = &relationship
		}
	}

	return nil
}
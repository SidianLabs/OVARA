package graph

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }
func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }

func TestTrustGraph_AddOrganization(t *testing.T) {
	tg := NewTrustGraph()
	err := tg.AddOrganization("acme.com", "Acme Corp", nil)
	if err != nil {
		t.Fatalf("AddOrganization failed: %v", err)
	}

	err = tg.AddOrganization("acme.com", "Acme Corp", nil)
	if err == nil {
		t.Error("expected duplicate organization error")
	}
}

func TestTrustGraph_RemoveOrganization(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("test.com", "Test Org", nil)

	err := tg.RemoveOrganization("test.com")
	if err != nil {
		t.Fatalf("RemoveOrganization failed: %v", err)
	}

	err = tg.RemoveOrganization("test.com")
	if err == nil {
		t.Error("expected error for missing organization")
	}
}

func TestTrustGraph_Federate(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := tg.Federate("a.com", "b.com", 0.8, [][]byte{pub})
	if err != nil {
		t.Fatalf("Federate failed: %v", err)
	}

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %d", len(neighbors))
	}
	if neighbors[0].TrustLevel != 0.8 {
		t.Errorf("trust level = %v, want 0.8", neighbors[0].TrustLevel)
	}
	if !neighbors[0].Active {
		t.Error("federation should be active")
	}
}

func TestTrustGraph_RevokeFederation(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	tg.Federate("a.com", "b.com", 0.9, nil)
	err := tg.RevokeFederation("a.com", "b.com")
	if err != nil {
		t.Fatalf("RevokeFederation failed: %v", err)
	}

	neighbors := tg.GetNeighbors("a.com")
	if neighbors[0].Active {
		t.Error("federation should be inactive after revocation")
	}
}

func TestTrustGraph_ComputeTrustPath_Direct(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.7, nil)

	path, err := tg.ComputeTrustPath("a.com", "b.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath failed: %v", err)
	}
	if !path.IsDirect() {
		t.Error("direct federation should have depth 1")
	}
	if path.Domains[0] != "a.com" || path.Domains[1] != "b.com" {
		t.Errorf("path domains = %v, want [a.com b.com]", path.Domains)
	}
}

func TestTrustGraph_ComputeTrustPath_Transitive(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("c.com", "Org C", nil)

	tg.Federate("a.com", "b.com", 0.9, nil)
	tg.Federate("b.com", "c.com", 0.8, nil)

	path, err := tg.ComputeTrustPath("a.com", "c.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath (transitive) failed: %v", err)
	}
	if path.Depth != 2 {
		t.Errorf("transitive path depth = %d, want 2", path.Depth)
	}
	if len(path.Domains) != 3 {
		t.Errorf("transitive path domains = %v, want 3 domains", path.Domains)
	}
}

func TestTrustGraph_ComputeTrustPath_NoPath(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	_, err := tg.ComputeTrustPath("a.com", "b.com")
	if err == nil {
		t.Error("expected error for no trust path")
	}
}

func TestTrustGraph_ComputeTrustPath_Self(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("self.com", "Self Org", nil)

	path, err := tg.ComputeTrustPath("self.com", "self.com")
	if err != nil {
		t.Fatalf("ComputeTrustPath (self) failed: %v", err)
	}
	if path.TrustScore != 1.0 {
		t.Errorf("self trust score = %v, want 1.0", path.TrustScore)
	}
	if path.Depth != 0 {
		t.Errorf("self path depth = %d, want 0", path.Depth)
	}
}

func TestTrustGraph_GetAllOrganizations(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("a.com", "Org A", nil)

	orgs := tg.GetAllOrganizations()
	if len(orgs) != 2 {
		t.Fatalf("expected 2 organizations, got %d", len(orgs))
	}
	if orgs[0].Domain != "a.com" {
		t.Errorf("organizations should be sorted by domain, got %s first", orgs[0].Domain)
	}
}

func TestTrustGraph_Snapshot(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.5, nil)

	snap := tg.Snapshot()
	if snap["node_count"].(int) != 2 {
		t.Errorf("snapshot node_count = %v, want 2", snap["node_count"])
	}
	if snap["edge_count"].(int) != 1 {
		t.Errorf("snapshot edge_count = %v, want 1", snap["edge_count"])
	}
}

func TestTrustPath_Hash(t *testing.T) {
	path := &TrustPath{
		Domains:    []TrustDomain{"a.com", "b.com", "c.com"},
		TrustScore: 0.72,
		Depth:      2,
	}

	hash1 := path.Hash()
	hash2 := path.Hash()

	if hash1 != hash2 {
		t.Error("TrustPath.Hash should be deterministic")
	}
	if len(hash1) != 64 {
		t.Errorf("hash length = %d, want 64 (SHA-256 hex)", len(hash1))
	}
}

func TestTrustGraph_TrustLevelBounds(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	err := tg.Federate("a.com", "b.com", -0.1, nil)
	if err == nil {
		t.Error("expected error for negative trust level")
	}

	err = tg.Federate("a.com", "b.com", 1.5, nil)
	if err == nil {
		t.Error("expected error for trust level > 1")
	}
}

func TestTrustGraph_Neighbors_Empty(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 0 {
		t.Errorf("expected 0 neighbors, got %d", len(neighbors))
	}
}

func TestTrustGraph_UpdateFederation(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	tg.Federate("a.com", "b.com", 0.5, nil)
	tg.Federate("a.com", "b.com", 0.9, nil)

	neighbors := tg.GetNeighbors("a.com")
	if neighbors[0].TrustLevel != 0.9 {
		t.Errorf("trust level after update = %v, want 0.9", neighbors[0].TrustLevel)
	}
}

func TestTrustGraph_RemoveOrgClearsEdges(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.AddOrganization("c.com", "Org C", nil)

	tg.Federate("a.com", "b.com", 0.5, nil)
	tg.Federate("a.com", "c.com", 0.5, nil)
	tg.RemoveOrganization("b.com")

	neighbors := tg.GetNeighbors("a.com")
	if len(neighbors) != 1 {
		t.Errorf("expected 1 neighbor after removal, got %d", len(neighbors))
	}
	if neighbors[0].TargetOrg != "c.com" {
		t.Errorf("remaining neighbor = %v, want c.com", neighbors[0].TargetOrg)
	}
}

func TestTrustGraph_GetNode(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)

	node, ok := tg.GetNode("a.com")
	if !ok {
		t.Fatal("GetNode returned false")
	}
	if node.Name != "Org A" {
		t.Errorf("name = %v, want Org A", node.Name)
	}

	_, ok = tg.GetNode("missing.com")
	if ok {
		t.Error("GetNode returned true for missing node")
	}
}

func TestTrustGraph_GetRelationship(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.5, nil)

	rel, ok := tg.GetRelationship("a.com", "b.com")
	if !ok {
		t.Fatal("GetRelationship returned false")
	}
	if rel.TrustLevel != 0.5 {
		t.Errorf("trust level = %v, want 0.5", rel.TrustLevel)
	}

	_, ok = tg.GetRelationship("b.com", "a.com")
	if ok {
		t.Error("GetRelationship returned true for reverse direction")
	}
}

func TestTrustGraph_SnapshotV2_Empty(t *testing.T) {
	tg := NewTrustGraph()
	snap := tg.SnapshotV2()
	if snap.Version != "v1" {
		t.Errorf("expected version v1, got %s", snap.Version)
	}
	if len(snap.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(snap.Nodes))
	}
	if len(snap.Relationships) != 0 {
		t.Errorf("expected 0 relationships, got %d", len(snap.Relationships))
	}
}

func TestTrustGraph_SnapshotV2_Populated(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.75, nil)

	snap := tg.SnapshotV2()
	if len(snap.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(snap.Nodes))
	}
	if len(snap.Relationships) != 1 {
		t.Errorf("expected 1 relationship, got %d", len(snap.Relationships))
	}
	if snap.Relationships[0].TrustLevel != 0.75 {
		t.Errorf("expected trust level 0.75, got %f", snap.Relationships[0].TrustLevel)
	}
}

func TestTrustGraph_RestoreFromSnapshot(t *testing.T) {
	original := NewTrustGraph()
	original.AddOrganization("a.com", "Org A", nil)
	original.AddOrganization("b.com", "Org B", nil)
	original.AddOrganization("c.com", "Org C", nil)
	original.Federate("a.com", "b.com", 0.5, nil)
	original.Federate("b.com", "c.com", 0.7, nil)
	original.Federate("a.com", "c.com", 0.9, nil)

	snap := original.SnapshotV2()

	// Restore into a fresh graph
	restored := NewTrustGraph()
	if err := restored.RestoreFromSnapshot(snap); err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	if len(restored.GetAllOrganizations()) != 3 {
		t.Errorf("expected 3 orgs in restored graph, got %d", len(restored.GetAllOrganizations()))
	}

	// Verify each relationship
	rel, ok := restored.GetRelationship("a.com", "b.com")
	if !ok || rel.TrustLevel != 0.5 {
		t.Error("a->b relationship not restored correctly")
	}
	rel, ok = restored.GetRelationship("b.com", "c.com")
	if !ok || rel.TrustLevel != 0.7 {
		t.Error("b->c relationship not restored correctly")
	}
	rel, ok = restored.GetRelationship("a.com", "c.com")
	if !ok || rel.TrustLevel != 0.9 {
		t.Error("a->c relationship not restored correctly")
	}
}

func TestTrustGraph_RestoreFromSnapshot_Replaces(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("old.com", "Old", nil)

	// Replace with new snapshot
	snap := GraphSnapshot{
		Version: "v1",
		Nodes: []OrganizationNode{
			{Domain: "new.com", Name: "New"},
		},
		Relationships: []TrustRelationship{},
	}
	if err := tg.RestoreFromSnapshot(snap); err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	if _, ok := tg.GetNode("old.com"); ok {
		t.Error("old.com should have been removed by restore")
	}
	if _, ok := tg.GetNode("new.com"); !ok {
		t.Error("new.com should be present after restore")
	}
}

func TestTrustGraph_SnapshotV2_RoundTrip_JSON(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.6, nil)

	snap := tg.SnapshotV2()

	// Serialize to JSON
	data, err := jsonMarshal(snap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Deserialize
	restored := GraphSnapshot{}
	if err := jsonUnmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Restore into new graph
	tg2 := NewTrustGraph()
	if err := tg2.RestoreFromSnapshot(restored); err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	rel, ok := tg2.GetRelationship("a.com", "b.com")
	if !ok || rel.TrustLevel != 0.6 {
		t.Error("relationship not preserved through JSON round-trip")
	}
}

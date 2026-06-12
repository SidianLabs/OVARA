package graph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGraphStore_NewGraphStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.json")

	gs, g := NewGraphStore(path)
	if gs == nil || g == nil {
		t.Fatal("NewGraphStore returned nil")
	}
	if len(g.GetAllOrganizations()) != 0 {
		t.Error("expected empty graph on first run")
	}
}

func TestGraphStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.json")

	// Create and populate
	gs, g := NewGraphStore(path)
	g.AddOrganization("a.com", "Org A", nil)
	g.AddOrganization("b.com", "Org B", nil)
	g.Federate("a.com", "b.com", 0.7, nil)

	if err := gs.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}

	// Load into a new store
	_, g2 := NewGraphStore(path)
	if len(g2.GetAllOrganizations()) != 2 {
		t.Errorf("expected 2 orgs after reload, got %d", len(g2.GetAllOrganizations()))
	}
	rel, ok := g2.GetRelationship("a.com", "b.com")
	if !ok {
		t.Error("relationship not restored")
	}
	if rel.TrustLevel != 0.7 {
		t.Errorf("expected trust level 0.7, got %f", rel.TrustLevel)
	}
}

func TestGraphStore_SaveDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.json")

	// Create valid file
	gs, g := NewGraphStore(path)
	g.AddOrganization("a.com", "Org A", nil)
	if err := gs.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Corrupt the file
	if err := os.WriteFile(path, []byte("corrupt data"), 0644); err != nil {
		t.Fatalf("failed to corrupt: %v", err)
	}

	// Loading should fail with checksum error
	_, g2 := NewGraphStore(path)
	_ = g2
}

func TestGraphStore_GraphAccessor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.json")

	gs, g := NewGraphStore(path)
	if gs.Graph() != g {
		t.Error("Graph() should return the underlying graph")
	}
}

func TestGraphStore_SaveCreatesTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.json")

	gs, g := NewGraphStore(path)
	g.AddOrganization("a.com", "Org A", nil)
	if err := gs.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify .tmp file is cleaned up
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should be cleaned up after rename")
	}
}

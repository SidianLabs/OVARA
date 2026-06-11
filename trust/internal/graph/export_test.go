package graph

import (
	"testing"
)

func TestTrustGraph_Export(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.8, nil)

	state, err := tg.Export()
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if state.Version != "1.0" {
		t.Errorf("version = %v, want 1.0", state.Version)
	}
	if len(state.Organizations) != 2 {
		t.Errorf("org count = %d, want 2", len(state.Organizations))
	}
	if len(state.Relationships) != 1 {
		t.Errorf("relationship count = %d, want 1", len(state.Relationships))
	}
}

func TestTrustGraph_ExportJSON(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)

	data, err := tg.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON is empty")
	}
}

func TestTrustGraph_Import(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)
	tg.Federate("a.com", "b.com", 0.8, nil)

	exported, _ := tg.Export()

	newGraph := NewTrustGraph()
	err := newGraph.Import(exported)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	orgs := newGraph.GetAllOrganizations()
	if len(orgs) != 2 {
		t.Errorf("org count after import = %d, want 2", len(orgs))
	}

	neighbors := newGraph.GetNeighbors("a.com")
	if len(neighbors) != 1 {
		t.Errorf("neighbors after import = %d, want 1", len(neighbors))
	}
}

func TestTrustGraph_ImportJSON(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)

	data, _ := tg.ExportJSON()

	newGraph := NewTrustGraph()
	err := newGraph.ImportJSON(data)
	if err != nil {
		t.Fatalf("ImportJSON failed: %v", err)
	}

	orgs := newGraph.GetAllOrganizations()
	if len(orgs) != 1 {
		t.Errorf("org count after import = %d, want 1", len(orgs))
	}
}

func TestTrustGraph_Import_Nil(t *testing.T) {
	tg := NewTrustGraph()
	err := tg.Import(nil)
	if err == nil {
		t.Error("expected error for nil import")
	}
}

func TestTrustGraph_Import_InvalidVersion(t *testing.T) {
	tg := NewTrustGraph()
	state := &ExportedTrustState{Version: ""}
	err := tg.Import(state)
	if err == nil {
		t.Error("expected error for missing version")
	}
}

func TestTrustGraph_Merge(t *testing.T) {
	tg1 := NewTrustGraph()
	tg1.AddOrganization("a.com", "Org A", nil)
	tg1.AddOrganization("b.com", "Org B", nil)
	tg1.Federate("a.com", "b.com", 0.8, nil)

	tg2 := NewTrustGraph()
	tg2.AddOrganization("b.com", "Org B", nil)
	tg2.AddOrganization("c.com", "Org C", nil)
	tg2.Federate("b.com", "c.com", 0.7, nil)

	err := tg1.Merge(tg2)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	orgs := tg1.GetAllOrganizations()
	if len(orgs) != 3 {
		t.Errorf("org count after merge = %d, want 3", len(orgs))
	}

	neighbors := tg1.GetNeighbors("b.com")
	if len(neighbors) != 1 {
		t.Errorf("b.com neighbors after merge = %d, want 1", len(neighbors))
	}
}

func TestTrustGraph_Merge_HigherTrustWins(t *testing.T) {
	tg1 := NewTrustGraph()
	tg1.AddOrganization("a.com", "Org A", nil)
	tg1.AddOrganization("b.com", "Org B", nil)
	tg1.Federate("a.com", "b.com", 0.5, nil)

	tg2 := NewTrustGraph()
	tg2.AddOrganization("a.com", "Org A", nil)
	tg2.AddOrganization("b.com", "Org B", nil)
	tg2.Federate("a.com", "b.com", 0.9, nil)

	tg1.Merge(tg2)

	neighbors := tg1.GetNeighbors("a.com")
	if neighbors[0].TrustLevel != 0.9 {
		t.Errorf("trust level after merge = %v, want 0.9", neighbors[0].TrustLevel)
	}
}

func TestTrustGraph_Import_ClearsExisting(t *testing.T) {
	tg := NewTrustGraph()
	tg.AddOrganization("a.com", "Org A", nil)
	tg.AddOrganization("b.com", "Org B", nil)

	exported, _ := tg.Export()

	newGraph := NewTrustGraph()
	newGraph.AddOrganization("x.com", "Org X", nil)
	newGraph.Import(exported)

	orgs := newGraph.GetAllOrganizations()
	found := false
	for _, o := range orgs {
		if o.Domain == "x.com" {
			found = true
			break
		}
	}
	if found {
		t.Error("import should clear existing organizations")
	}
}
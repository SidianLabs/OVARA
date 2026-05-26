package policy

import (
	"testing"
	"time"
)

func TestInMemoryPolicyHistory_Add(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	entry := &PolicyHistoryEntry{
		Version:   "v1",
		RuleCount: 5,
		Source:    PolicySourcePromote,
	}
	id := store.Add(entry)
	if id == "" {
		t.Errorf("expected non-empty id")
	}
}

func TestInMemoryPolicyHistory_Get(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	entry := &PolicyHistoryEntry{
		Version:   "v1",
		RuleCount: 5,
		Source:    PolicySourcePromote,
	}
	id := store.Add(entry)

	found, ok := store.Get(id)
	if !ok {
		t.Errorf("expected entry to be found")
	}
	if found.Version != "v1" {
		t.Errorf("expected version v1, got %s", found.Version)
	}
}

func TestInMemoryPolicyHistory_Get_NotFound(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Errorf("expected not found")
	}
}

func TestInMemoryPolicyHistory_List(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	store.Add(&PolicyHistoryEntry{Version: "v1", Source: PolicySourcePromote})
	store.Add(&PolicyHistoryEntry{Version: "v2", Source: PolicySourcePromote})
	store.Add(&PolicyHistoryEntry{Version: "v3", Source: PolicySourceRollback})

	list := store.List()
	if len(list) != 3 {
		t.Errorf("expected 3 entries, got %d", len(list))
	}
}

func TestInMemoryPolicyHistory_Latest(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	e1 := &PolicyHistoryEntry{Version: "v1", Source: PolicySourcePromote}
	e2 := &PolicyHistoryEntry{Version: "v2", Source: PolicySourcePromote}
	e3 := &PolicyHistoryEntry{Version: "v3", Source: PolicySourcePromote}

	store.Add(e1)
	time.Sleep(10 * time.Millisecond)
	store.Add(e2)
	time.Sleep(10 * time.Millisecond)
	store.Add(e3)

	latest, ok := store.Latest()
	if !ok {
		t.Errorf("expected entry to be found")
	}
	if latest.Version != "v3" {
		t.Errorf("expected version v3, got %s", latest.Version)
	}
}

func TestInMemoryPolicyHistory_Latest_Empty(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	_, ok := store.Latest()
	if ok {
		t.Errorf("expected not found for empty store")
	}
}

func TestInMemoryPolicyHistory_Clear(t *testing.T) {
	store := NewInMemoryPolicyHistory()

	store.Add(&PolicyHistoryEntry{Version: "v1", Source: PolicySourcePromote})
	store.Add(&PolicyHistoryEntry{Version: "v2", Source: PolicySourcePromote})

	store.Clear()

	list := store.List()
	if len(list) != 0 {
		t.Errorf("expected 0 entries after clear, got %d", len(list))
	}
}

func TestPolicyHistorySnapshotter_SnapshotFromStore(t *testing.T) {
	snapshotter := NewPolicyHistorySnapshotter()

	store := NewStore("v1-test")
	store.ClearRules()
	store.AddRule(Rule{ActionType: "shell", Environment: "local", Allow: true})

	id := snapshotter.SnapshotFromStore(store, PolicySourcePromote, "", "gw_test")
	if id == "" {
		t.Errorf("expected non-empty id")
	}

	entry, ok := snapshotter.Get(id)
	if !ok {
		t.Errorf("expected entry to be found")
	}
	if entry.Version != "v1-test" {
		t.Errorf("expected version v1-test, got %s", entry.Version)
	}
	if entry.RuleCount != 1 {
		t.Errorf("expected 1 rule, got %d", entry.RuleCount)
	}
	if entry.Source != PolicySourcePromote {
		t.Errorf("expected source promote, got %s", entry.Source)
	}
}

func TestPolicyHistorySnapshotter_List(t *testing.T) {
	snapshotter := NewPolicyHistorySnapshotter()

	store1 := NewStore("v1")
	store1.ClearRules()
	store1.AddRule(Rule{ActionType: "shell", Environment: "local", Allow: true})
	snapshotter.SnapshotFromStore(store1, PolicySourcePromote, "", "")

	store2 := NewStore("v2")
	store2.ClearRules()
	store2.AddRule(Rule{ActionType: "git.pull", Environment: "*", Allow: true})
	snapshotter.SnapshotFromStore(store2, PolicySourcePromote, "v1", "")

	list := snapshotter.List()
	if len(list) != 2 {
		t.Errorf("expected 2 entries, got %d", len(list))
	}
}

func TestPolicyHistorySources(t *testing.T) {
	if PolicySourcePromote != "promote" {
		t.Errorf("expected promote, got %s", PolicySourcePromote)
	}
	if PolicySourceRollback != "rollback" {
		t.Errorf("expected rollback, got %s", PolicySourceRollback)
	}
	if PolicySourceRestore != "restore" {
		t.Errorf("expected restore, got %s", PolicySourceRestore)
	}
	if PolicySourceReload != "reload" {
		t.Errorf("expected reload, got %s", PolicySourceReload)
	}
}

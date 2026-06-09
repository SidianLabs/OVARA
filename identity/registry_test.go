package identity

import (
	"testing"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := r.Register(id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := r.Get(id.ID)
	if !ok {
		t.Fatal("Get returned false for registered identity")
	}
	if got.ID != id.ID {
		t.Errorf("got ID = %s, want %s", got.ID, id.ID)
	}
	if r.Count() != 1 {
		t.Errorf("count = %d, want 1", r.Count())
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	r := NewRegistry()

	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := r.Register(id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Register(id); err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()

	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("Get returned true for nonexistent identity")
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()

	id1, _, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	id2, _, _ := NewAgentIdentity("ovara", "agent-2", "owner-2")

	r.Register(id1)
	r.Register(id2)

	list := r.List()
	if len(list) != 2 {
		t.Errorf("list length = %d, want 2", len(list))
	}
}

func TestRegistry_ListActive(t *testing.T) {
	r := NewRegistry()

	id1, _, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	id2, _, _ := NewAgentIdentity("ovara", "agent-2", "owner-2")

	r.Register(id1)
	r.Register(id2)

	id1.Suspend()

	active := r.ListActive()
	if len(active) != 1 {
		t.Errorf("active count = %d, want 1", len(active))
	}
	if active[0].ID != id2.ID {
		t.Errorf("active ID = %s, want %s", active[0].ID, id2.ID)
	}
}

func TestRegistry_Suspend(t *testing.T) {
	r := NewRegistry()

	id, _, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	r.Register(id)

	if err := r.Suspend(id.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := r.Get(id.ID)
	if got.IsActive() {
		t.Error("identity should be suspended")
	}

	if err := r.Suspend("nonexistent"); err == nil {
		t.Error("expected error for nonexistent identity")
	}
}

func TestRegistry_Revoke(t *testing.T) {
	r := NewRegistry()

	id, _, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	r.Register(id)

	if err := r.Revoke(id.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := r.Get(id.ID)
	if got.Lifecycle != LifecycleRevoked {
		t.Errorf("lifecycle = %v, want revoked", got.Lifecycle)
	}

	if err := r.Revoke("nonexistent"); err == nil {
		t.Error("expected error for nonexistent identity")
	}
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Errorf("count = %d, want 0", r.Count())
	}

	id, _, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	r.Register(id)
	if r.Count() != 1 {
		t.Errorf("count = %d, want 1", r.Count())
	}
}

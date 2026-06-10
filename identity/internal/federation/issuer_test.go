package federation

import (
	"testing"

	"ovara.identity/internal/store"
)

func TestIssuer_CreateIdentity(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	id, _, err := issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ID == "" {
		t.Error("id is empty")
	}
	if !id.IsActive() {
		t.Error("identity should be active")
	}

	got, ok := r.Get(id.ID)
	if !ok {
		t.Fatal("identity not found in registry")
	}
	if got.ID != id.ID {
		t.Errorf("got ID = %s, want %s", got.ID, id.ID)
	}
}

func TestIssuer_CreateIdentity_DuplicateRejected(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	_, _, err := issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, _, err = issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err == nil {
		t.Error("expected error for duplicate subject_id")
	}
}

func TestIssuer_IssueLease(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	id, priv, err := issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lease, err := issuer.IssueLease(id.ID, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lease.LeaseID == "" {
		t.Error("lease_id is empty")
	}
	if lease.Issuer != id.ID {
		t.Errorf("issuer = %s, want %s", lease.Issuer, id.ID)
	}

	stored, ok := ls.Get(lease.LeaseID)
	if !ok {
		t.Fatal("lease not found in store")
	}
	if stored.LeaseID != lease.LeaseID {
		t.Errorf("stored lease ID = %s, want %s", stored.LeaseID, lease.LeaseID)
	}
}

func TestIssuer_IssueLease_IssuerNotInRegistry(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	_, err := issuer.IssueLease("nonexistent", nil, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for unknown issuer")
	}
}

func TestIssuer_IssueLease_IssuerRevoked(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	id, priv, err := issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r.Revoke(id.ID)

	_, err = issuer.IssueLease(id.ID, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err == nil {
		t.Error("expected error for revoked issuer")
	}
}

func TestIssuer_RevokeLease(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	id, priv, err := issuer.CreateIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lease, err := issuer.IssueLease(id.ID, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := issuer.RevokeLease(lease.LeaseID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored, _ := ls.Get(lease.LeaseID)
	if !stored.IsExpired() {
		t.Error("revoked lease should be expired")
	}
}

func TestIssuer_RevokeLease_NotFound(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	if err := issuer.RevokeLease("nonexistent"); err == nil {
		t.Error("expected error for nonexistent lease")
	}
}

func TestIssuer_ActiveLeasesFor(t *testing.T) {
	r := store.NewRegistry()
	ls := store.NewLeaseStore()
	issuer := NewIssuer(r, ls)

	id, priv, _ := issuer.CreateIdentity("ovara", "agent-1", "owner-1")

	l1, _ := issuer.IssueLease(id.ID, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	_, _ = issuer.IssueLease(id.ID, priv, "agent-3", []string{"shell"}, "repo:*", 1, 0)

	active := issuer.ActiveLeasesFor("agent-2")
	if len(active) != 1 {
		t.Fatalf("active count = %d, want 1", len(active))
	}
	if active[0].LeaseID != l1.LeaseID {
		t.Errorf("active lease ID = %s, want %s", active[0].LeaseID, l1.LeaseID)
	}
}

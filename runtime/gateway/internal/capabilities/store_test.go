package capabilities

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestStore_Track(t *testing.T) {
	store := NewInMemoryStore()

	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
	}

	id := store.Track(lease, "gw_test")
	if id != "cap_123" {
		t.Errorf("expected cap_123, got %s", id)
	}
}

func TestStore_Get(t *testing.T) {
	store := NewInMemoryStore()

	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}
	store.Track(lease, "gw_test")

	tracked, ok := store.Get("cap_123")
	if !ok {
		t.Errorf("expected to find cap_123")
	}
	if tracked.Lease.Subject != "agent-001" {
		t.Errorf("expected subject agent-001, got %s", tracked.Lease.Subject)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	store := NewInMemoryStore()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Errorf("expected not found")
	}
}

func TestStore_List(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_2",
		Issuer:         "admin",
		Subject:        "agent-002",
		AllowedActions: []string{"git.pull"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	list := store.List()
	if len(list) != 2 {
		t.Errorf("expected 2 leases, got %d", len(list))
	}
}

func TestStore_ListActive(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_2",
		Issuer:         "admin",
		Subject:        "agent-002",
		AllowedActions: []string{"git.pull"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(-1 * time.Hour),
	}, "gw_test")

	active := store.ListActive()
	if len(active) != 1 {
		t.Errorf("expected 1 active lease, got %d", len(active))
	}
	if active[0].Lease.LeaseID != "cap_1" {
		t.Errorf("expected cap_1 to be active")
	}
}

func TestStore_ListRevoked(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_2",
		Issuer:         "admin",
		Subject:        "agent-002",
		AllowedActions: []string{"git.pull"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	store.Revoke("cap_1", "test revocation")

	revoked := store.ListRevoked()
	if len(revoked) != 1 {
		t.Errorf("expected 1 revoked lease, got %d", len(revoked))
	}
	if revoked[0].Lease.LeaseID != "cap_1" {
		t.Errorf("expected cap_1 to be revoked")
	}
}

func TestStore_Revoke(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	tracked, ok := store.Revoke("cap_1", "security incident")
	if !ok {
		t.Errorf("expected revoke to succeed")
	}
	if tracked.RevocationReason != "security incident" {
		t.Errorf("expected reason 'security incident', got %s", tracked.RevocationReason)
	}
	if tracked.RevokedAt == nil {
		t.Errorf("expected revoked_at to be set")
	}
}

func TestStore_Revoke_NotFound(t *testing.T) {
	store := NewInMemoryStore()

	_, ok := store.Revoke("nonexistent", "test")
	if ok {
		t.Errorf("expected revoke to fail for nonexistent")
	}
}

func TestStore_Revoke_AlreadyRevoked(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	store.Revoke("cap_1", "first revocation")

	tracked, ok := store.Revoke("cap_1", "second revocation")
	if !ok {
		t.Errorf("expected revoke to succeed even if already revoked")
	}
	if tracked.RevocationReason != "first revocation" {
		t.Errorf("expected first revocation reason preserved, got %s", tracked.RevocationReason)
	}
}

func TestStore_IsRevoked(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	if store.IsRevoked("cap_1") {
		t.Errorf("expected cap_1 to not be revoked initially")
	}

	store.Revoke("cap_1", "test")

	if !store.IsRevoked("cap_1") {
		t.Errorf("expected cap_1 to be revoked")
	}
}

func TestStore_IsRevoked_NotFound(t *testing.T) {
	store := NewInMemoryStore()

	if store.IsRevoked("nonexistent") {
		t.Errorf("expected nonexistent to not be revoked")
	}
}

func TestStore_Clear(t *testing.T) {
	store := NewInMemoryStore()

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_1",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	store.Clear()

	list := store.List()
	if len(list) != 0 {
		t.Errorf("expected 0 leases after clear, got %d", len(list))
	}
}

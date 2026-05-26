package capabilities

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestFileStore_TrackAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	lease := &models.CapabilityLease{
		LeaseID:        "cap_fp_001",
		Issuer:         "admin",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
	}

	id := store.Track(lease, "gw_test")
	if id != "cap_fp_001" {
		t.Errorf("expected cap_fp_001, got %s", id)
	}

	time.Sleep(10 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read persisted file: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("persisted file is empty")
	}
}

func TestFileStore_ReloadOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store1, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_reload_001",
		Issuer:         "admin",
		Subject:        "agent-reload",
		AllowedActions: []string{"git.pull"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_reload_002",
		Issuer:         "admin",
		Subject:        "agent-reload-2",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	time.Sleep(20 * time.Millisecond)

	store2, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}

	tracked, ok := store2.Get("cap_reload_001")
	if !ok {
		t.Fatalf("cap_reload_001 not found after reload")
	}
	if tracked.Lease.Subject != "agent-reload" {
		t.Errorf("expected subject agent-reload, got %s", tracked.Lease.Subject)
	}

	tracked2, ok := store2.Get("cap_reload_002")
	if !ok {
		t.Fatalf("cap_reload_002 not found after reload")
	}
	if tracked2.Lease.Subject != "agent-reload-2" {
		t.Errorf("expected subject agent-reload-2, got %s", tracked2.Lease.Subject)
	}

	list := store2.List()
	if len(list) != 2 {
		t.Errorf("expected 2 leases after reload, got %d", len(list))
	}
}

func TestFileStore_RevokeAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store1, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_revoke_reload",
		Issuer:         "admin",
		Subject:        "agent-revoke",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	store1.Revoke("cap_revoke_reload", "security incident")

	time.Sleep(20 * time.Millisecond)

	store2, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}

	if !store2.IsRevoked("cap_revoke_reload") {
		t.Errorf("expected cap_revoke_reload to be revoked after reload")
	}

	tracked, ok := store2.Get("cap_revoke_reload")
	if !ok {
		t.Fatalf("cap_revoke_reload not found after reload")
	}
	if tracked.RevocationReason != "security incident" {
		t.Errorf("expected revocation reason preserved, got %s", tracked.RevocationReason)
	}
}

func TestFileStore_ListActiveAfterReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store1, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_active_001",
		Issuer:         "admin",
		Subject:        "agent-active",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_expired_001",
		Issuer:         "admin",
		Subject:        "agent-expired",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(-1 * time.Hour),
	}, "gw_test")

	time.Sleep(20 * time.Millisecond)

	store2, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}

	active := store2.ListActive()
	if len(active) != 1 {
		t.Errorf("expected 1 active lease after reload, got %d", len(active))
	}
	if active[0].Lease.LeaseID != "cap_active_001" {
		t.Errorf("expected cap_active_001 to be active")
	}

	revoked := store2.ListRevoked()
	if len(revoked) != 0 {
		t.Errorf("expected 0 revoked leases, got %d", len(revoked))
	}
}

func TestFileStore_Stats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_stats_001",
		Issuer:         "admin",
		Subject:        "agent-stats",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_stats_002",
		Issuer:         "admin",
		Subject:        "agent-stats-2",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")

	store.Revoke("cap_stats_001", "test")

	total, active, revoked := store.Stats()
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
	if active != 1 {
		t.Errorf("expected active=1, got %d", active)
	}
	if revoked != 1 {
		t.Errorf("expected revoked=1, got %d", revoked)
	}
}

func TestFileStore_ReloadRevokedStillDenies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store1, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store1.Track(&models.CapabilityLease{
		LeaseID:        "cap_deny_test",
		Issuer:         "admin",
		Subject:        "agent-deny",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}, "gw_test")
	store1.Revoke("cap_deny_test", "security incident")

	time.Sleep(20 * time.Millisecond)

	store2, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore reload failed: %v", err)
	}

	if !store2.IsRevoked("cap_deny_test") {
		t.Errorf("expected cap_deny_test to be revoked after reload")
	}
}

func TestFileStore_EvictOldest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store, err := NewFileBackedStore(path, 3, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		store.Track(&models.CapabilityLease{
			LeaseID:        "cap_evict_" + string(rune('a'+i)),
			Issuer:         "admin",
			Subject:        "agent-evict",
			AllowedActions: []string{"shell"},
			ResourceScope:   "*",
			Expiry:         time.Now().Add(1 * time.Hour),
		}, "gw_test")
	}

	time.Sleep(10 * time.Millisecond)

	list := store.List()
	if len(list) != 3 {
		t.Errorf("expected 3 leases after eviction, got %d", len(list))
	}
}

func TestFileStore_Clear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	store.Track(&models.CapabilityLease{
		LeaseID:        "cap_clear_001",
		Issuer:         "admin",
		Subject:        "agent-clear",
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

func TestFileStore_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")

	store, err := NewFileBackedStore(path, 100, 0)
	if err != nil {
		t.Fatalf("NewFileBackedStore failed: %v", err)
	}

	_, ok := store.Get("nonexistent")
	if ok {
		t.Errorf("expected not found for nonexistent lease")
	}

	if store.IsRevoked("nonexistent") {
		t.Errorf("expected nonexistent to not be revoked")
	}

	_, ok = store.Revoke("nonexistent", "test")
	if ok {
		t.Errorf("expected revoke to fail for nonexistent")
	}
}

package capabilities

import (
	"testing"
	"time"
)

func TestHistoryStore_Append(t *testing.T) {
	store := NewHistoryStore()

	store.Append(LeaseTrackedEntry("cap_h_001", "gw1", "agent-1", "admin"))
	store.Append(LeaseUsedEntry("cap_h_001", "gw1"))
	store.Append(LeaseRevokedEntry("cap_h_001", "gw1", "security incident", "agent-1", "admin"))

	entries := store.ListByLeaseID("cap_h_001")
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Event != "tracked" {
		t.Errorf("expected first event to be 'tracked', got %s", entries[0].Event)
	}
	if entries[1].Event != "used" {
		t.Errorf("expected second event to be 'used', got %s", entries[1].Event)
	}
	if entries[2].Event != "revoked" {
		t.Errorf("expected third event to be 'revoked', got %s", entries[2].Event)
	}
}

func TestHistoryStore_ListRecent(t *testing.T) {
	store := NewHistoryStore()

	for i := 0; i < 10; i++ {
		store.Append(LeaseTrackedEntry("cap_recent_"+string(rune('0'+i)), "gw1", "agent", "admin"))
	}

	recent := store.ListRecent(5)
	if len(recent) != 5 {
		t.Errorf("expected 5 recent entries, got %d", len(recent))
	}

	recentAll := store.ListRecent(0)
	if len(recentAll) != 10 {
		t.Errorf("expected all 10 entries, got %d", len(recentAll))
	}
}

func TestHistoryStore_ListBySubject(t *testing.T) {
	store := NewHistoryStore()

	store.Append(LeaseTrackedEntry("cap_s_001", "gw1", "agent-x", "admin"))
	store.Append(LeaseTrackedEntry("cap_s_002", "gw1", "agent-y", "admin"))
	store.Append(LeaseTrackedEntry("cap_s_003", "gw1", "agent-x", "admin"))

	entries := store.ListBySubject("agent-x")
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for agent-x, got %d", len(entries))
	}
}

func TestHistoryStore_Count(t *testing.T) {
	store := NewHistoryStore()

	if store.Count() != 0 {
		t.Errorf("expected count 0, got %d", store.Count())
	}

	store.Append(LeaseTrackedEntry("cap_c_001", "gw1", "agent", "admin"))
	if store.Count() != 1 {
		t.Errorf("expected count 1, got %d", store.Count())
	}

	store.Append(LeaseTrackedEntry("cap_c_002", "gw1", "agent", "admin"))
	if store.Count() != 2 {
		t.Errorf("expected count 2, got %d", store.Count())
	}
}

func TestHistoryStore_Clear(t *testing.T) {
	store := NewHistoryStore()

	store.Append(LeaseTrackedEntry("cap_clr_001", "gw1", "agent", "admin"))
	store.Append(LeaseTrackedEntry("cap_clr_002", "gw1", "agent", "admin"))

	store.Clear()

	if store.Count() != 0 {
		t.Errorf("expected count 0 after clear, got %d", store.Count())
	}
}

func TestLeaseHistoryEntry_Fields(t *testing.T) {
	before := time.Now().UTC()
	entry := LeaseTrackedEntry("cap_f_001", "gw_test", "agent-test", "issuer-test")
	after := time.Now().UTC()

	if entry.LeaseID != "cap_f_001" {
		t.Errorf("expected lease_id cap_f_001, got %s", entry.LeaseID)
	}
	if entry.Event != "tracked" {
		t.Errorf("expected event tracked, got %s", entry.Event)
	}
	if entry.GatewayID != "gw_test" {
		t.Errorf("expected gateway_id gw_test, got %s", entry.GatewayID)
	}
	if entry.Subject != "agent-test" {
		t.Errorf("expected subject agent-test, got %s", entry.Subject)
	}
	if entry.Issuer != "issuer-test" {
		t.Errorf("expected issuer issuer-test, got %s", entry.Issuer)
	}
	if entry.Timestamp.Before(before) || entry.Timestamp.After(after) {
		t.Errorf("timestamp out of range: %v", entry.Timestamp)
	}
}

func TestLeaseRevokedEntry(t *testing.T) {
	entry := LeaseRevokedEntry("cap_r_001", "gw1", "compromise", "agent-x", "admin")

	if entry.LeaseID != "cap_r_001" {
		t.Errorf("expected lease_id cap_r_001, got %s", entry.LeaseID)
	}
	if entry.Event != "revoked" {
		t.Errorf("expected event revoked, got %s", entry.Event)
	}
	if entry.Reason != "compromise" {
		t.Errorf("expected reason 'compromise', got %s", entry.Reason)
	}
}

func TestLeaseUsedEntry(t *testing.T) {
	entry := LeaseUsedEntry("cap_u_001", "gw1")

	if entry.LeaseID != "cap_u_001" {
		t.Errorf("expected lease_id cap_u_001, got %s", entry.LeaseID)
	}
	if entry.Event != "used" {
		t.Errorf("expected event used, got %s", entry.Event)
	}
	if entry.GatewayID != "gw1" {
		t.Errorf("expected gateway_id gw1, got %s", entry.GatewayID)
	}
}

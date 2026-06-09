package identity

import (
	"testing"
	"time"
)

func TestLeaseStore_StoreAndGet(t *testing.T) {
	s := NewLeaseStore()

	issuer, priv, err := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lease, err := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := s.Store(lease); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := s.Get(lease.LeaseID)
	if !ok {
		t.Fatal("Get returned false for stored lease")
	}
	if got.LeaseID != lease.LeaseID {
		t.Errorf("got lease ID = %s, want %s", got.LeaseID, lease.LeaseID)
	}
	if s.Count() != 1 {
		t.Errorf("count = %d, want 1", s.Count())
	}
}

func TestLeaseStore_StoreDuplicate(t *testing.T) {
	s := NewLeaseStore()

	issuer, priv, _ := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	lease, _ := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)

	s.Store(lease)
	if err := s.Store(lease); err == nil {
		t.Error("expected error for duplicate lease")
	}
}

func TestLeaseStore_GetMissing(t *testing.T) {
	s := NewLeaseStore()
	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("Get returned true for nonexistent lease")
	}
}

func TestLeaseStore_List(t *testing.T) {
	s := NewLeaseStore()

	issuer, priv, _ := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	l1, _ := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	l2, _ := IssueCapabilityLease(issuer, priv, "agent-3", []string{"git.push"}, "repo:other", 30, 0)

	s.Store(l1)
	s.Store(l2)

	list := s.List()
	if len(list) != 2 {
		t.Errorf("list length = %d, want 2", len(list))
	}
}

func TestLeaseStore_ListBySubject(t *testing.T) {
	s := NewLeaseStore()

	issuer, priv, _ := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	l1, _ := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)
	l2, _ := IssueCapabilityLease(issuer, priv, "agent-3", []string{"shell"}, "repo:*", 30, 0)

	s.Store(l1)
	s.Store(l2)

	bySubject := s.ListBySubject("agent-2")
	if len(bySubject) != 1 {
		t.Errorf("subject list length = %d, want 1", len(bySubject))
	}
	if bySubject[0].LeaseID != l1.LeaseID {
		t.Errorf("got lease ID = %s, want %s", bySubject[0].LeaseID, l1.LeaseID)
	}
}

func TestLeaseStore_ListByIssuer(t *testing.T) {
	s := NewLeaseStore()

	issuer1, priv1, _ := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	issuer2, priv2, _ := NewAgentIdentity("ovara", "issuer-2", "owner-1")

	l1, _ := IssueCapabilityLease(issuer1, priv1, "agent-a", []string{"shell"}, "repo:*", 30, 0)
	l2, _ := IssueCapabilityLease(issuer2, priv2, "agent-b", []string{"shell"}, "repo:*", 30, 0)

	s.Store(l1)
	s.Store(l2)

	byIssuer := s.ListByIssuer(issuer1.ID)
	if len(byIssuer) != 1 {
		t.Errorf("issuer list length = %d, want 1", len(byIssuer))
	}
}

func TestLeaseStore_ListActive(t *testing.T) {
	s := NewLeaseStore()

	issuer, priv, _ := NewAgentIdentity("ovara", "issuer-1", "owner-1")
	l1, _ := IssueCapabilityLease(issuer, priv, "agent-2", []string{"shell"}, "repo:*", 30, 0)

	l2, _ := IssueCapabilityLease(issuer, priv, "agent-3", []string{"shell"}, "repo:*", 1, 0)
	l2.Expiry = l2.IssuedAt.Add(-1 * time.Hour)

	s.Store(l1)
	s.Store(l2)

	active := s.ListActive()
	if len(active) != 1 {
		t.Errorf("active count = %d, want 1 (one expired)", len(active))
	}
	if active[0].LeaseID != l1.LeaseID {
		t.Errorf("active lease ID = %s, want %s", active[0].LeaseID, l1.LeaseID)
	}
}

func TestLeaseStore_Count_Empty(t *testing.T) {
	s := NewLeaseStore()
	if s.Count() != 0 {
		t.Errorf("count = %d, want 0", s.Count())
	}
}

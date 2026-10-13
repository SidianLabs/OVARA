package approval

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func clockAt(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func pendingFor(t *testing.T, svc *Service, decision string) *ApprovalRequest {
	t.Helper()
	a, err := svc.CreateApproval(&CreateRequest{
		DecisionID: decision, ActionType: models.ActionType("http.request"),
		Resource: "POST https://api.example/x", Environment: models.EnvironmentDev, AgentID: "agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A pending approval older than the TTL reads as expired, is not listed as
// pending, and can no longer be approved.
func TestPendingApprovalExpires(t *testing.T) {
	for name, store := range map[string]Store{
		"memory": NewInMemoryStore(),
		"file":   mustFileStore(t),
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			svc := NewService(store)
			svc.SetNow(clockAt(&now))
			if svc.PendingTTL() != DefaultPendingTTL || DefaultPendingTTL != 10*time.Minute {
				t.Fatalf("default TTL %s", svc.PendingTTL())
			}
			old := pendingFor(t, svc, "dec_old")
			old2 := pendingFor(t, svc, "dec_old2")
			// old was created 11 minutes before "now"
			now = now.Add(11 * time.Minute)
			fresh2 := pendingFor(t, svc, "dec_fresh2")

			got, err := svc.GetApproval(old.ApprovalID)
			if err != nil || got.Status != StatusExpired {
				t.Fatalf("old approval: %v %v", got, err)
			}
			for _, p := range svc.ListPending() {
				if p.ApprovalID == old.ApprovalID || p.ApprovalID == old2.ApprovalID {
					t.Errorf("expired approval %s listed as pending", p.ApprovalID)
				}
			}
			if l := svc.ListByStatus(StatusExpired); len(l) != 2 {
				t.Errorf("expired list: %d", len(l))
			}
			if _, err := svc.Approve(old.ApprovalID, "operator"); !errors.Is(err, ErrApprovalExpired) {
				t.Fatalf("approving an expired approval: %v", err)
			}
			if got, _ := svc.GetApproval(old.ApprovalID); got.Status != StatusExpired {
				t.Fatalf("a refused approve changed the status to %s", got.Status)
			}
			if a, err := svc.Approve(fresh2.ApprovalID, "operator"); err != nil || a.Status != StatusApproved {
				t.Fatalf("fresh approval: %v %v", a, err)
			}
			// an approved approval does not expire later
			now = now.Add(time.Hour)
			if got, _ := svc.GetApproval(fresh2.ApprovalID); got.Status != StatusApproved {
				t.Fatalf("approved became %s", got.Status)
			}
		})
	}
}

func TestPendingTTLConfigurable(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	svc.SetPendingTTL(time.Minute)
	a := pendingFor(t, svc, "dec_1")
	now = now.Add(61 * time.Second)
	if got, _ := svc.GetApproval(a.ApprovalID); got.Status != StatusExpired {
		t.Fatalf("status %s", got.Status)
	}
	// zero disables expiry
	svc.SetPendingTTL(0)
	if got, _ := svc.GetApproval(a.ApprovalID); got.Status != StatusPending {
		t.Fatalf("status %s with expiry off", got.Status)
	}
	if _, err := svc.Approve(a.ApprovalID, "operator"); err != nil {
		t.Fatal(err)
	}
}

// Pending approvals come back oldest first.
func TestListPendingOldestFirst(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, pendingFor(t, svc, "dec_"+string(rune('a'+i))).ApprovalID)
		now = now.Add(time.Second)
	}
	// the in-memory store iterates a map, so its own order varies per call
	for round := 0; round < 20; round++ {
		l := svc.ListPending()
		for i := range ids {
			if l[i].ApprovalID != ids[i] {
				t.Fatalf("round %d: position %d is %s, want %s", round, i, l[i].ApprovalID, ids[i])
			}
		}
	}
}

func mustFileStore(t *testing.T) Store {
	t.Helper()
	s, err := NewFileBackedStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

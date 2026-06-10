package store

import (
	"testing"
	"time"

	"ovara.services.approval/internal/models"
	"github.com/google/uuid"
)

func newTestApproval() *models.Approval {
	return &models.Approval{
		ID:          "appr_" + uuid.New().String()[:12],
		GatewayID:   "gw-001",
		DecisionID:  "dec-001",
		ActionType:  "shell.execute",
		Resource:    "sudo",
		AgentID:     "agt-001",
		RequestedBy: "operator",
		State:       models.StatePending,
		ExpiresAt:   time.Now().UTC().Add(30 * time.Minute),
		CreatedAt:   time.Now().UTC(),
	}
}

func TestCreateAndGet(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestApproval()

	if err := s.Create(a); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ActionType != a.ActionType {
		t.Errorf("ActionType = %v, want %v", got.ActionType, a.ActionType)
	}
}

func TestCreateDuplicate(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestApproval()

	s.Create(a)
	err := s.Create(a)
	if err == nil {
		t.Error("expected duplicate error")
	}
}

func TestCreateMaxSize(t *testing.T) {
	s := NewMemoryStore(2)
	s.Create(newTestApproval())
	s.Create(newTestApproval())

	err := s.Create(newTestApproval())
	if err == nil {
		t.Error("expected store full error")
	}
}

func TestGetNotFound(t *testing.T) {
	s := NewMemoryStore(100)
	_, err := s.Get("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestListByState(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestApproval()
	a1.State = models.StatePending
	s.Create(a1)

	a2 := newTestApproval()
	a2.State = models.StateApproved
	s.Create(a2)

	a3 := newTestApproval()
	a3.State = models.StatePending
	s.Create(a3)

	pending, _ := s.List(ListFilter{State: models.StatePending})
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}

	approved, _ := s.List(ListFilter{State: models.StateApproved})
	if len(approved) != 1 {
		t.Errorf("expected 1 approved, got %d", len(approved))
	}
}

func TestListByGateway(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestApproval()
	a1.GatewayID = "gw-a"
	s.Create(a1)

	a2 := newTestApproval()
	a2.GatewayID = "gw-b"
	s.Create(a2)

	results, _ := s.List(ListFilter{GatewayID: "gw-a"})
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}
}

func TestListPagination(t *testing.T) {
	s := NewMemoryStore(100)

	for range 5 {
		s.Create(newTestApproval())
	}

	results, _ := s.List(ListFilter{Limit: 3})
	if len(results) != 3 {
		t.Errorf("expected 3, got %d", len(results))
	}

	page2, _ := s.List(ListFilter{Limit: 3, Offset: 3})
	if len(page2) != 2 {
		t.Errorf("expected 2, got %d", len(page2))
	}
}

func TestResolve(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestApproval()
	s.Create(a)

	err := s.Resolve(a.ID, models.StateApproved, "admin", "looks good")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	got, _ := s.Get(a.ID)
	if got.State != models.StateApproved {
		t.Errorf("State = %v, want approved", got.State)
	}
	if got.ResolvedBy != "admin" {
		t.Errorf("ResolvedBy = %v, want admin", got.ResolvedBy)
	}
	if got.ResolvedAt == nil {
		t.Error("ResolvedAt should not be nil")
	}
}

func TestResolveAlreadyResolved(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestApproval()
	s.Create(a)

	s.Resolve(a.ID, models.StateApproved, "admin", "ok")
	err := s.Resolve(a.ID, models.StateDenied, "admin2", "changed mind")
	if err == nil {
		t.Error("expected already resolved error")
	}
}

func TestExpireOlderThan(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestApproval()
	a1.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	s.Create(a1)

	a2 := newTestApproval()
	a2.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	s.Create(a2)

	a3 := newTestApproval()
	a3.CreatedAt = time.Now().UTC()
	a3.State = models.StateApproved
	s.Create(a3)

	count, err := s.ExpireOlderThan(time.Now().UTC().Add(-30 * time.Minute))
	if err != nil {
		t.Fatalf("ExpireOlderThan failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 expired, got %d", count)
	}

	expired, _ := s.List(ListFilter{State: models.StateExpired})
	if len(expired) != 2 {
		t.Errorf("expected 2 in expired state, got %d", len(expired))
	}
}

func TestCount(t *testing.T) {
	s := NewMemoryStore(100)
	for range 7 {
		s.Create(newTestApproval())
	}
	if s.Count() != 7 {
		t.Errorf("count = %d, want 7", s.Count())
	}
}

func TestEmptyList(t *testing.T) {
	s := NewMemoryStore(100)
	results, err := s.List(ListFilter{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if results == nil {
		t.Error("List should return empty slice, not nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

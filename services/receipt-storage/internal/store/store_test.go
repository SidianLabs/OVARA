package store

import (
	"testing"
	"time"

	"ovara.services.receipt/internal/models"
	"github.com/google/uuid"
)

func newTestReceipt() *models.Receipt {
	return &models.Receipt{
		ID:             "rcpt_" + uuid.New().String()[:12],
		DecisionID:     "dec-" + uuid.New().String()[:8],
		GatewayID:      "gw-001",
		OrganizationID: "org-acme",
		ActionType:     "shell.execute",
		Resource:       "npm install",
		Decision:       "allow",
		AgentID:        "agt-001",
		TrustScore:     0.95,
		Payload:        `{"stdout":"ok"}`,
		Signature:      "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		IssuedAt:       time.Now().UTC(),
		ArchivedAt:     time.Now().UTC(),
	}
}

func TestArchiveAndGet(t *testing.T) {
	s := NewMemoryStore(1000)
	r := newTestReceipt()

	if err := s.Archive(r); err != nil {
		t.Fatalf("Archive failed: %v", err)
	}

	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ActionType != "shell.execute" {
		t.Errorf("ActionType = %v, want shell.execute", got.ActionType)
	}
}

func TestArchiveDuplicate(t *testing.T) {
	s := NewMemoryStore(1000)
	r := newTestReceipt()

	s.Archive(r)
	err := s.Archive(r)
	if err == nil {
		t.Error("expected duplicate archive error")
	}
}

func TestArchiveMaxSize(t *testing.T) {
	s := NewMemoryStore(2)
	s.Archive(newTestReceipt())
	s.Archive(newTestReceipt())

	err := s.Archive(newTestReceipt())
	if err == nil {
		t.Error("expected store full error")
	}
}

func TestGetNotFound(t *testing.T) {
	s := NewMemoryStore(1000)
	_, err := s.Get("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestListByOrganization(t *testing.T) {
	s := NewMemoryStore(1000)

	r1 := newTestReceipt()
	r1.OrganizationID = "org-a"
	s.Archive(r1)

	r2 := newTestReceipt()
	r2.OrganizationID = "org-b"
	s.Archive(r2)

	r3 := newTestReceipt()
	r3.OrganizationID = "org-a"
	s.Archive(r3)

	results, _ := s.List(ListFilter{OrganizationID: "org-a"})
	if len(results) != 2 {
		t.Errorf("expected 2, got %d", len(results))
	}
}

func TestListByDecision(t *testing.T) {
	s := NewMemoryStore(1000)

	r1 := newTestReceipt()
	r1.Decision = "allow"
	s.Archive(r1)

	r2 := newTestReceipt()
	r2.Decision = "deny"
	s.Archive(r2)

	allows, _ := s.List(ListFilter{Decision: "allow"})
	if len(allows) != 1 {
		t.Errorf("expected 1 allow, got %d", len(allows))
	}
}

func TestListByDateRange(t *testing.T) {
	s := NewMemoryStore(1000)

	r1 := newTestReceipt()
	r1.IssuedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.Archive(r1)

	r2 := newTestReceipt()
	r2.IssuedAt = time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC)
	s.Archive(r2)

	r3 := newTestReceipt()
	r3.IssuedAt = time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	s.Archive(r3)

	results, _ := s.List(ListFilter{
		StartDate: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		EndDate:   time.Date(2025, 9, 30, 0, 0, 0, 0, time.UTC),
	})
	if len(results) != 1 {
		t.Errorf("expected 1 in date range, got %d", len(results))
	}
}

func TestListPagination(t *testing.T) {
	s := NewMemoryStore(1000)
	for range 10 {
		s.Archive(newTestReceipt())
	}

	page1, _ := s.List(ListFilter{Limit: 4})
	if len(page1) != 4 {
		t.Errorf("expected 4, got %d", len(page1))
	}

	page2, _ := s.List(ListFilter{Limit: 4, Offset: 4})
	if len(page2) != 4 {
		t.Errorf("expected 4, got %d", len(page2))
	}
}

func TestVerify(t *testing.T) {
	s := NewMemoryStore(1000)
	r := newTestReceipt()
	r.Signature = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s.Archive(r)

	result, err := s.Verify(r.ID)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid signature")
	}
	if result.ReceiptDigest == "" {
		t.Error("receipt digest should not be empty")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	s := NewMemoryStore(1000)
	r := newTestReceipt()
	r.Signature = ""
	s.Archive(r)

	result, _ := s.Verify(r.ID)
	if result.Valid {
		t.Error("expected invalid signature")
	}
}

func TestVerifyNotFound(t *testing.T) {
	s := NewMemoryStore(1000)
	_, err := s.Verify("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestCount(t *testing.T) {
	s := NewMemoryStore(1000)
	for range 15 {
		s.Archive(newTestReceipt())
	}
	if s.Count() != 15 {
		t.Errorf("count = %d, want 15", s.Count())
	}
}

func TestCountByOrg(t *testing.T) {
	s := NewMemoryStore(1000)

	for range 3 {
		r := newTestReceipt()
		r.OrganizationID = "org-x"
		s.Archive(r)
	}
	for range 5 {
		r := newTestReceipt()
		r.OrganizationID = "org-y"
		s.Archive(r)
	}

	if s.CountByOrg("org-x") != 3 {
		t.Errorf("org-x count = %d, want 3", s.CountByOrg("org-x"))
	}
	if s.CountByOrg("org-y") != 5 {
		t.Errorf("org-y count = %d, want 5", s.CountByOrg("org-y"))
	}
}

func TestReceiptDigest(t *testing.T) {
	r := newTestReceipt()
	d1 := r.Digest()
	d2 := r.Digest()

	if d1 != d2 {
		t.Error("Digest should be deterministic")
	}
	if len(d1) != 64 {
		t.Errorf("digest length = %d, want 64", len(d1))
	}
}

func TestEmptyList(t *testing.T) {
	s := NewMemoryStore(1000)
	results, err := s.List(ListFilter{})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if results == nil {
		t.Error("List should return empty slice, not nil")
	}
}

package approval

import (
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestService_CreateApproval(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_123",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo test",
		Environment: models.EnvironmentLocal,
		AgentID:     "agent-001",
	}

	approval, err := svc.CreateApproval(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approval.ApprovalID == "" {
		t.Error("approval_id should not be empty")
	}
	if approval.Status != StatusPending {
		t.Errorf("status = %v, want pending", approval.Status)
	}
	if approval.DecisionID != "dec_123" {
		t.Errorf("decision_id = %v, want dec_123", approval.DecisionID)
	}
}

func TestService_Approve(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_456",
		ActionType:  models.ActionTypeGitPush,
		Resource:    "git:acme/api",
		Environment: models.EnvironmentDev,
	}

	approval, _ := svc.CreateApproval(req)
	approved, err := svc.Approve(approval.ApprovalID, "admin@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approved.Status != StatusApproved {
		t.Errorf("status = %v, want approved", approved.Status)
	}
	if approved.ResolvedBy != "admin@example.com" {
		t.Errorf("resolved_by = %v, want admin@example.com", approved.ResolvedBy)
	}
	if approved.ResolvedAt == nil {
		t.Error("resolved_at should not be nil")
	}
}

func TestService_Deny(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_789",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:rm -rf /",
		Environment: models.EnvironmentProduction,
	}

	approval, _ := svc.CreateApproval(req)
	denied, err := svc.Deny(approval.ApprovalID, "admin@example.com", "too risky")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied.Status != StatusDenied {
		t.Errorf("status = %v, want denied", denied.Status)
	}
	if denied.Reason != "too risky" {
		t.Errorf("reason = %v, want too risky", denied.Reason)
	}
}

func TestService_Approve_NonPending(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_abc",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
	}

	approval, _ := svc.CreateApproval(req)
	svc.Approve(approval.ApprovalID, "admin")

	_, err := svc.Approve(approval.ApprovalID, "admin2")
	if err == nil {
		t.Error("expected error when approving non-pending approval")
	}
}

func TestService_ListPending(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	svc.CreateApproval(&CreateRequest{
		DecisionID:  "dec_1",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:one",
		Environment: models.EnvironmentLocal,
	})
	svc.CreateApproval(&CreateRequest{
		DecisionID:  "dec_2",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:two",
		Environment: models.EnvironmentLocal,
	})

	pending := svc.ListPending()
	if len(pending) != 2 {
		t.Errorf("len(pending) = %d, want 2", len(pending))
	}
}

func TestService_ResumeAction_Approved(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_resume",
		ActionType:  models.ActionTypeGitPush,
		Resource:    "git:acme/api",
		Environment: models.EnvironmentDev,
	}

	approval, _ := svc.CreateApproval(req)
	svc.Approve(approval.ApprovalID, "admin")

	canResume, err := svc.ResumeAction(approval.ApprovalID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !canResume {
		t.Error("expected canResume to be true for approved action")
	}
}

func TestService_ResumeAction_NotApproved(t *testing.T) {
	store := NewInMemoryStore()
	svc := NewService(store)

	req := &CreateRequest{
		DecisionID:  "dec_denied",
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
	}

	approval, _ := svc.CreateApproval(req)

	_, err := svc.ResumeAction(approval.ApprovalID)
	if err == nil {
		t.Error("expected error when resuming non-approved action")
	}
}

func TestInMemoryStore_Create(t *testing.T) {
	store := NewInMemoryStore()
	req := &ApprovalRequest{
		ApprovalID: "apr_test123",
		Status:     StatusPending,
	}

	err := store.Create(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.Create(req)
	if err == nil {
		t.Error("expected error when creating duplicate approval")
	}
}

func TestInMemoryStore_Get(t *testing.T) {
	store := NewInMemoryStore()
	req := &ApprovalRequest{
		ApprovalID: "apr_get456",
		Status:     StatusPending,
	}
	store.Create(req)

	got, err := store.Get("apr_get456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ApprovalID != "apr_get456" {
		t.Errorf("approval_id = %v, want apr_get456", got.ApprovalID)
	}

	_, err = store.Get("apr_notfound")
	if err == nil {
		t.Error("expected error when approval not found")
	}
}

func TestApprovalRequest_Approve(t *testing.T) {
	req := &ApprovalRequest{
		ApprovalID: "apr_approve",
		Status:     StatusPending,
	}
	req.Approve("admin@example.com")

	if req.Status != StatusApproved {
		t.Errorf("status = %v, want approved", req.Status)
	}
	if req.ResolvedBy != "admin@example.com" {
		t.Errorf("resolved_by = %v", req.ResolvedBy)
	}
	if req.ResolvedAt == nil {
		t.Error("resolved_at should not be nil")
	}
}

func TestApprovalRequest_IsPending(t *testing.T) {
	req := &ApprovalRequest{Status: StatusPending}
	if !req.IsPending() {
		t.Error("expected IsPending to return true")
	}

	req.Status = StatusApproved
	if req.IsPending() {
		t.Error("expected IsPending to return false for approved")
	}
}
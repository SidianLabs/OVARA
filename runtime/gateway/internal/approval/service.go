package approval

import (
	"fmt"

	"github.com/google/uuid"
)

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) CreateApproval(req *CreateRequest) (*ApprovalRequest, error) {
	if req.DecisionID == "" {
		return nil, fmt.Errorf("decision_id is required")
	}
	if req.ActionType == "" {
		return nil, fmt.Errorf("action_type is required")
	}

	approvalID := fmt.Sprintf("apr_%s", uuid.New().String()[:16])
	approval := req.ToApproval(approvalID)

	if err := s.store.Create(approval); err != nil {
		return nil, fmt.Errorf("creating approval: %w", err)
	}

	return approval, nil
}

func (s *Service) Approve(approvalID, resolvedBy string) (*ApprovalRequest, error) {
	approval, err := s.store.Get(approvalID)
	if err != nil {
		return nil, err
	}
	if !approval.IsPending() {
		return nil, fmt.Errorf("approval is not pending: %s", approval.Status)
	}
	approval.Approve(resolvedBy)
	if err := s.store.Update(approval); err != nil {
		return nil, fmt.Errorf("updating approval: %w", err)
	}
	return approval, nil
}

func (s *Service) Deny(approvalID, resolvedBy, reason string) (*ApprovalRequest, error) {
	approval, err := s.store.Get(approvalID)
	if err != nil {
		return nil, err
	}
	if !approval.IsPending() {
		return nil, fmt.Errorf("approval is not pending: %s", approval.Status)
	}
	approval.Deny(resolvedBy, reason)
	if err := s.store.Update(approval); err != nil {
		return nil, fmt.Errorf("updating approval: %w", err)
	}
	return approval, nil
}

func (s *Service) GetApproval(approvalID string) (*ApprovalRequest, error) {
	return s.store.Get(approvalID)
}

func (s *Service) ListPending() []*ApprovalRequest {
	return s.store.ListByStatus(StatusPending)
}

func (s *Service) ResumeAction(approvalID string) (*ResumeResult, error) {
	approval, err := s.store.Get(approvalID)
	if err != nil {
		return nil, err
	}
	if approval.Status != StatusApproved {
		return nil, fmt.Errorf("approval not approved: %s", approval.Status)
	}
	return &ResumeResult{
		Approved:  true,
		ApprovalID: approvalID,
		DecisionID: approval.DecisionID,
		ActionType: string(approval.ActionType),
		Resource:   approval.Resource,
	}, nil
}

type ResumeResult struct {
	Approved   bool   `json:"approved"`
	ApprovalID string `json:"approval_id"`
	DecisionID string `json:"decision_id"`
	ActionType string `json:"action_type"`
	Resource   string `json:"resource"`
}
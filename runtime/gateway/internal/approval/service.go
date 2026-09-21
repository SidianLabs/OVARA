package approval

import (
	"fmt"
	"log"

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

	log.Printf("APPROVAL created approval_id=%s decision_id=%s action_type=%s agent_id=%s environment=%s",
		approvalID, req.DecisionID, req.ActionType, req.AgentID, req.Environment)

	return approval, nil
}

func (s *Service) Approve(approvalID, resolvedBy string) (*ApprovalRequest, error) {
	// Atomic check+mutate under the store lock: a concurrent deny cannot
	// interleave between the pending check and the mutation.
	approval, err := s.store.Resolve(approvalID, StatusApproved, resolvedBy, "")
	if err != nil {
		return nil, err
	}

	log.Printf("APPROVAL approved approval_id=%s resolved_by=%s action_type=%s decision_id=%s",
		approvalID, resolvedBy, approval.ActionType, approval.DecisionID)

	return approval, nil
}

func (s *Service) Deny(approvalID, resolvedBy, reason string) (*ApprovalRequest, error) {
	approval, err := s.store.Resolve(approvalID, StatusDenied, resolvedBy, reason)
	if err != nil {
		return nil, err
	}

	log.Printf("APPROVAL denied approval_id=%s resolved_by=%s reason=%q action_type=%s decision_id=%s",
		approvalID, resolvedBy, reason, approval.ActionType, approval.DecisionID)

	return approval, nil
}

func (s *Service) GetApproval(approvalID string) (*ApprovalRequest, error) {
	return s.store.Get(approvalID)
}

func (s *Service) ListAll() []*ApprovalRequest {
	return s.store.ListAll()
}

func (s *Service) ListPending() []*ApprovalRequest {
	return s.store.ListByStatus(StatusPending)
}

func (s *Service) ListByStatus(status Status) []*ApprovalRequest {
	return s.store.ListByStatus(status)
}

func (s *Service) ListByDecision(decisionID string) []*ApprovalRequest {
	return s.store.ListByDecision(decisionID)
}

// ResumeAction consumes the approval's single-use resume token atomically.
// A second resume for the same approval fails, preventing replay.
func (s *Service) ResumeAction(approvalID string) (*ResumeResult, error) {
	approval, err := s.store.ConsumeResume(approvalID)
	if err != nil {
		return nil, err
	}

	result := &ResumeResult{
		Approved:     true,
		ApprovalID:    approvalID,
		DecisionID:    approval.DecisionID,
		ActionType:    string(approval.ActionType),
		Resource:      approval.Resource,
		TrustScore:    approval.TrustScore,
		TrustLevel:    string(approval.TrustLevel),
		AnomalyCodes:  approval.AnomalyCodes,
		ShieldActive:  approval.ShieldActive,
		Restricted:    approval.Restricted,
	}

	log.Printf("APPROVAL resumed approval_id=%s decision_id=%s action_type=%s",
		approvalID, approval.DecisionID, approval.ActionType)

	return result, nil
}

type ResumeResult struct {
	Approved     bool     `json:"approved"`
	ApprovalID   string   `json:"approval_id"`
	DecisionID   string   `json:"decision_id"`
	ActionType   string   `json:"action_type"`
	Resource     string   `json:"resource"`
	TrustScore   float64  `json:"trust_score,omitempty"`
	TrustLevel   string   `json:"trust_level,omitempty"`
	AnomalyCodes []string `json:"anomaly_codes,omitempty"`
	ShieldActive bool     `json:"shield_active,omitempty"`
	Restricted   bool     `json:"restricted,omitempty"`
}
package evaluator

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

func TestEvaluator_ValidateRequest(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	tests := []struct {
		name     string
		req      models.ActionRequest
		wantDec  models.Decision
		wantCode models.ReasonCode
	}{
		{
			name: "missing action_type yields deny",
			req: models.ActionRequest{
				Resource:    "repo:acme/api",
				Environment: models.EnvironmentLocal,
			},
			wantDec:  models.DecisionDeny,
			wantCode: models.ReasonActionNotAllowed,
		},
		{
			name: "missing resource yields deny",
			req: models.ActionRequest{
				ActionType:  models.ActionTypeShell,
				Environment: models.EnvironmentLocal,
			},
			wantDec:  models.DecisionDeny,
			wantCode: models.ReasonActionNotAllowed,
		},
		{
			name: "missing environment yields deny",
			req: models.ActionRequest{
				ActionType: models.ActionTypeShell,
				Resource:   "repo:acme/api",
			},
			wantDec:  models.DecisionDeny,
			wantCode: models.ReasonActionNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ev.Evaluate(&tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", resp.Decision, tt.wantDec)
			}
		})
	}
}

func TestEvaluator_AllowAction(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeGitPull,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
	}

	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("decision = %v, reasons = %v", resp.Decision, resp.ReasonCodes)
	if resp.Decision != models.DecisionAllow {
		t.Errorf("decision = %v, want allow", resp.Decision)
	}
}

func TestEvaluator_EscalateAction(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
	}

	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != models.DecisionEscalate {
		t.Errorf("decision = %v, want escalate", resp.Decision)
	}
	if !resp.RequiresApproval {
		t.Errorf("requires_approval = false, want true")
	}
}

func TestEvaluator_ProductionEscalates(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeGitPull,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentProduction,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
	}

	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != models.DecisionEscalate {
		t.Errorf("production git.pull should escalate, got %v", resp.Decision)
	}
}

func TestEvaluator_CapabilityExpired(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeGitPush,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentDev,
		CapabilityLease: &models.CapabilityLease{
			LeaseID:        "cap_123",
			Issuer:         "test-issuer",
			Subject:        "agent-1",
			AllowedActions: []string{"git.push"},
			ResourceScope:  "repo:acme/api",
			Expiry:         time.Now().Add(-1 * time.Hour),
			DelegationDepth: 1,
		},
	}

	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != models.DecisionDeny {
		t.Errorf("decision = %v, want deny for expired capability", resp.Decision)
	}
}

func TestEvaluator_ReceiptStub(t *testing.T) {
	store := policy.NewStore("test")
	ev := New(store)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeGitPush,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentDev,
	}

	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReceiptStub == nil {
		t.Fatal("receipt_stub is nil, want non-nil")
	}
	if resp.ReceiptStub.ReceiptID == "" {
		t.Error("receipt_stub.receipt_id is empty")
	}
	if resp.ReceiptStub.ActionDigest == "" {
		t.Error("receipt_stub.action_digest is empty")
	}
	if resp.ReceiptStub.PolicyVersion != "test" {
		t.Errorf("policy_version = %v, want test", resp.ReceiptStub.PolicyVersion)
	}
}

func TestActionRequest_Validate(t *testing.T) {
	valid := models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentLocal,
	}
	if errs := valid.Validate(); len(errs) != 0 {
		t.Errorf("valid request has %d errors, want 0: %v", len(errs), errs)
	}

	missingType := models.ActionRequest{
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentLocal,
	}
	errs := missingType.Validate()
	if len(errs) != 1 || errs[0] != "action_type is required" {
		t.Errorf("missing action_type errors = %v, want [action_type is required]", errs)
	}
}
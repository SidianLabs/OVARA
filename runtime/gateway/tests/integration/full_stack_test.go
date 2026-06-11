package integration

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/trust"
)

func newTestEvaluator() *evaluator.Evaluator {
	store := policy.NewStore("v1-test")
	return evaluator.New(store)
}

func newTestRequest(actionType, resource, env string) *models.ActionRequest {
	return &models.ActionRequest{
		ActionType:  models.ActionType(actionType),
		Resource:    resource,
		Environment: models.Environment(env),
	}
}

func newTestIdentity(issuer, subjectID string) *models.AgentIdentity {
	return &models.AgentIdentity{
		Issuer:    issuer,
		SubjectID: subjectID,
		Owner:     "test-team",
	}
}

func newTestLease(leaseID, issuer, subject string, actions []string) *models.CapabilityLease {
	return &models.CapabilityLease{
		LeaseID:         leaseID,
		Issuer:          issuer,
		Subject:         subject,
		AllowedActions:  actions,
		ResourceScope:   "*",
		Expiry:          time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
		IssuedAt:        time.Now(),
	}
}

func newTestEvaluatorWithShield() (*evaluator.Evaluator, *trust.ShieldStore) {
	shield := trust.NewShieldStore()
	p := policy.NewStore("v1-test")
	eval := evaluator.NewWithShield(p, shield)
	return eval, shield
}

func TestFullStack_DecisionToReceipt(t *testing.T) {
	eval := newTestEvaluator()
	req := &models.ActionRequest{
		ActionType:  models.ActionTypeGitPull,
		Resource:    "repo:acme/api",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
	}

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	if resp.Decision != models.DecisionAllow {
		t.Errorf("decision = %q, want %q, reasons=%v", resp.Decision, models.DecisionAllow, resp.ReasonCodes)
	}
	if resp.DecisionID == "" {
		t.Error("decision_id should not be empty")
	}
	if resp.ReceiptStub == nil {
		t.Error("receipt_stub should not be nil")
	}
	if resp.TrustContext == nil {
		t.Error("trust_context should not be nil")
	}
}

func TestFullStack_EscalateWorkflow(t *testing.T) {
	eval := newTestEvaluator()
	req := newTestRequest("shell", "shell:ls", "local")
	req.AgentIdentity = newTestIdentity("ovara", "agent-001")

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	t.Logf("decision=%v reasons=%v", resp.Decision, resp.ReasonCodes)
	if resp.TrustContext == nil {
		t.Error("trust_context should not be nil")
	}
}

func TestFullStack_DenyWorkflow(t *testing.T) {
	eval := newTestEvaluator()

	req := newTestRequest("shell", "", "local")
	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != models.DecisionDeny {
		t.Errorf("decision = %q, want %q", resp.Decision, models.DecisionDeny)
	}
}

func TestFullStack_IdentityVerification(t *testing.T) {
	eval := newTestEvaluator()
	req := newTestRequest("git.pull", "repo:acme/api", "local")
	req.AgentIdentity = newTestIdentity("ovara", "agent-001")

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	t.Logf("decision=%v reasons=%v", resp.Decision, resp.ReasonCodes)
}

func TestFullStack_IdentityInvalid(t *testing.T) {
	eval := newTestEvaluator()
	req := newTestRequest("git.pull", "repo:acme/api", "local")
	req.AgentIdentity = &models.AgentIdentity{}

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != models.DecisionDeny {
		t.Errorf("decision = %q, want %q", resp.Decision, models.DecisionDeny)
	}
}

func TestFullStack_CapabilityLeaseValidation(t *testing.T) {
	eval := newTestEvaluator()
	req := newTestRequest("git.pull", "repo:acme/api", "local")
	req.CapabilityLease = newTestLease("lse_001", "ovara", "agent-001", []string{"git.pull"})

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	t.Logf("decision=%v reasons=%v", resp.Decision, resp.ReasonCodes)
}

func TestFullStack_CapabilityLeaseExpired(t *testing.T) {
	eval := newTestEvaluator()
	req := newTestRequest("git.pull", "repo:acme/api", "local")
	lease := newTestLease("lse_001", "ovara", "agent-001", []string{"git.pull"})
	lease.Expiry = time.Now().Add(-1 * time.Hour)
	req.CapabilityLease = lease

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != models.DecisionDeny {
		t.Errorf("decision = %q, want %q", resp.Decision, models.DecisionDeny)
	}
}

func TestFullStack_ShieldAutoRestrict(t *testing.T) {
	eval, shield := newTestEvaluatorWithShield()

	for i := 0; i < 10; i++ {
		req := newTestRequest("shell", "shell:ls", "production")
		req.AgentIdentity = newTestIdentity("ovara", "agent-risky")
		eval.Evaluate(req)
	}

	restricted := shield.IsRestricted("agent-risky")
	t.Logf("restricted=%v", restricted)
}

func TestFullStack_TrustStats(t *testing.T) {
	eval, shield := newTestEvaluatorWithShield()

	for i := 0; i < 3; i++ {
		req := newTestRequest("shell", "shell:ls", "local")
		req.AgentIdentity = newTestIdentity("ovara", "agent-trust-test")
		eval.Evaluate(req)
	}

	stats := shield.GetStats("agent-trust-test")
	t.Logf("risk_count=%d last_decision=%s", stats.RiskCount, stats.LastDecision)
}

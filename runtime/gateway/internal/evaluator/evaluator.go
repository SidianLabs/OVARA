package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/trust"
)

type Evaluator struct {
	policyStore *policy.Store
	validator   *identity.Validator
	shieldStore *trust.ShieldStore
}

func New(p *policy.Store) *Evaluator {
	return &Evaluator{
		policyStore: p,
		validator:   identity.NewValidator(),
		shieldStore: trust.NewShieldStore(),
	}
}

func NewWithShield(p *policy.Store, ss *trust.ShieldStore) *Evaluator {
	return &Evaluator{
		policyStore: p,
		validator:   identity.NewValidator(),
		shieldStore: ss,
	}
}

type EvalResult struct {
	Decision         models.Decision
	ReasonCodes      []models.ReasonCode
	TrustScore       float64
	RequiresApproval bool
	PolicyVersion    string
}

func (e *Evaluator) Evaluate(req *models.ActionRequest) (*models.DecisionResponse, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return &models.DecisionResponse{
			Decision:    models.DecisionDeny,
			ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
		}, nil
	}

	actionRules := e.policyStore.RulesForAction(string(req.ActionType))
	envRules := e.policyStore.RulesForEnvironment(string(req.Environment))

	var reasons []models.ReasonCode
	var decision models.Decision
	var requiresApproval bool
	trustScore := 0.5
	policyVersion := e.policyStore.Version()

	trustResult := trust.NewEvaluator(e.shieldStore).Evaluate(req)

	if trustResult.Restricted {
		reasons = append(reasons, models.ReasonContainmentActive)
		decision = models.DecisionEscalate
		requiresApproval = true
	}

	if decision == "" {
		identityResult := e.validator.ValidateAgentIdentity(req.AgentIdentity)
		if !identityResult.Valid {
			for range identityResult.Reasons {
				reasons = append(reasons, models.ReasonIdentityInvalid)
			}
			decision = models.DecisionDeny
		}
	}

	if decision == "" && req.CapabilityLease != nil {
		leaseResult := e.validator.ValidateCapabilityLease(req.CapabilityLease)
		if !leaseResult.Valid {
			for _, reason := range leaseResult.Reasons {
				if strings.Contains(reason, "expiry") {
					reasons = append(reasons, models.ReasonCapabilityExpiry)
				} else {
					reasons = append(reasons, models.ReasonCapabilityNotAllowed)
				}
			}
			decision = models.DecisionDeny
		}

		if decision == "" {
			scopeResult := e.validator.ValidateCapabilityLeaseScope(req.CapabilityLease, string(req.ActionType), req.Resource)
			if !scopeResult.Valid {
				for _, reason := range scopeResult.Reasons {
					if strings.Contains(reason, "scope") {
						reasons = append(reasons, models.ReasonCapabilityScope)
					} else {
						reasons = append(reasons, models.ReasonCapabilityNotAllowed)
					}
				}
				decision = models.DecisionDeny
			}
		}
	}

	if decision == "" {
		outcome := e.evaluateRules(actionRules, envRules, req)
		if outcome.Denied {
			reasons = append(reasons, outcome.Reason)
			decision = models.DecisionDeny
		} else if outcome.Escalate {
			reasons = append(reasons, outcome.Reason)
			if trustResult.ShouldEscalate() {
				reasons = append(reasons, models.ReasonTrustEscalate)
			}
			for _, sig := range trustResult.AnomalySignals {
				reasons = append(reasons, models.ReasonCode(sig.Code))
			}
			requiresApproval = true
			decision = models.DecisionEscalate
		} else {
			reasons = append(reasons, outcome.Reason)
			decision = models.DecisionAllow
		}
	}

	trustScore = trustResult.Score
	if trustResult.ShouldEscalate() && decision == models.DecisionAllow {
		reasons = append(reasons, models.ReasonTrustEscalate)
		for _, sig := range trustResult.AnomalySignals {
			reasons = append(reasons, models.ReasonCode(sig.Code))
		}
		decision = models.DecisionEscalate
		requiresApproval = true
	}

	if req.AgentIdentity != nil && decision != "" {
		e.shieldStore.RecordDecision(req.AgentIdentity.SubjectID, string(decision))
		if e.shieldStore.ShouldAutoRestrict(req.AgentIdentity.SubjectID, 3) {
			e.shieldStore.AutoRestrictAfterRepeatedRisk(req.AgentIdentity.SubjectID, 3)
		}
	}

	receiptStub := e.buildReceiptStub(req, decision, policyVersion, trustScore)

	trustCtx := &models.TrustContext{
		Score:          trustScore,
		Level:          trustResult.Level,
		AnomalySignals: trustResult.AnomalySignals,
		ShieldActive:   trustResult.ShieldActive,
		Restricted:     trustResult.Restricted,
		RiskCount:      trustResult.RiskCount,
		EvaluationTime: time.Now().UTC(),
	}

	return &models.DecisionResponse{
		DecisionID:       generateID(),
		Decision:         decision,
		ReasonCodes:      reasons,
		TrustScore:       trustScore,
		TrustLevel:      trustResult.Level,
		RequiresApproval: requiresApproval,
		ReceiptStub:      receiptStub,
		TrustContext:     trustCtx,
	}, nil
}

type RuleOutcome struct {
	Allowed  bool
	Denied   bool
	Escalate bool
	Reason   models.ReasonCode
}

func (e *Evaluator) evaluateRules(actionRules, envRules []policy.Rule, req *models.ActionRequest) RuleOutcome {
	for _, r := range actionRules {
		if r.Deny {
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}
	for _, r := range envRules {
		if r.Deny {
			if req.Environment == models.EnvironmentProduction {
				return RuleOutcome{Denied: true, Reason: models.ReasonProductionDenied}
			}
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}

	for _, r := range actionRules {
		if r.Allow && r.ActionType != "*" {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow}
		}
	}
	for _, r := range envRules {
		if r.Allow && r.Environment != "*" {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow}
		}
	}

	for _, r := range actionRules {
		if r.Escalate && r.ActionType != "*" {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}
	for _, r := range envRules {
		if r.Escalate && r.Environment != "*" {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}

	return RuleOutcome{Allowed: true, Reason: models.ReasonAllowed}
}

func (e *Evaluator) shouldEscalate(actionRules, envRules []policy.Rule, req *models.ActionRequest) bool {
	return false
}

func (e *Evaluator) buildReceiptStub(req *models.ActionRequest, decision models.Decision, policyVersion string, trustScore float64) *models.ReceiptStub {
	return &models.ReceiptStub{
		ReceiptID:        generateID(),
		ActionDigest:      actionDigest(req),
		ActionType:       string(req.ActionType),
		Resource:         req.Resource,
		PolicyVersion:    policyVersion,
		TrustContextScore: trustScore,
		IssuedAt:         time.Now().UTC(),
	}
}

func generateID() string {
	return fmt.Sprintf("dec_%s", uuid.New().String()[:16])
}

func actionDigest(req *models.ActionRequest) string {
	h := sha256.New()
	h.Write([]byte(string(req.ActionType)))
	h.Write([]byte(req.Resource))
	if req.AgentIdentity != nil {
		h.Write([]byte(req.AgentIdentity.SubjectID))
	}
	if req.CapabilityLease != nil {
		h.Write([]byte(req.CapabilityLease.LeaseID))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}
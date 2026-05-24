package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

type Evaluator struct {
	policyStore *policy.Store
}

func New(p *policy.Store) *Evaluator {
	return &Evaluator{policyStore: p}
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
			ReasonCodes:  []models.ReasonCode{models.ReasonActionNotAllowed},
		}, nil
	}

	actionRules := e.policyStore.RulesForAction(string(req.ActionType))
	envRules := e.policyStore.RulesForEnvironment(string(req.Environment))

	var reasons []models.ReasonCode
	var decision models.Decision
	var requiresApproval bool
	trustScore := 0.5
	policyVersion := e.policyStore.Version()

	if req.CapabilityLease != nil {
		if req.CapabilityLease.Expiry.Before(time.Now()) {
			reasons = append(reasons, models.ReasonCapabilityExpiry)
			decision = models.DecisionDeny
		} else if !e.capabilityAllowsAction(req.CapabilityLease, string(req.ActionType), req.Resource) {
			reasons = append(reasons, models.ReasonActionNotAllowed)
			decision = models.DecisionDeny
		}
	}

	if decision == "" {
		allowed, reason := e.evaluateRules(actionRules, envRules, req)
		if !allowed {
			reasons = append(reasons, reason)
			decision = models.DecisionDeny
		} else {
			escalate := e.shouldEscalate(actionRules, envRules, req)
			if escalate {
				reasons = append(reasons, models.ReasonEscalate)
				requiresApproval = true
				decision = models.DecisionEscalate
			} else {
				reasons = append(reasons, models.ReasonAllowed)
				decision = models.DecisionAllow
			}
		}
	}

	receiptStub := e.buildReceiptStub(req, decision, policyVersion, trustScore)

	return &models.DecisionResponse{
		DecisionID:       generateID(),
		Decision:         decision,
		ReasonCodes:      reasons,
		TrustScore:       trustScore,
		RequiresApproval: requiresApproval,
		ReceiptStub:      receiptStub,
	}, nil
}

func (e *Evaluator) capabilityAllowsAction(lease *models.CapabilityLease, actionType, resource string) bool {
	for _, a := range lease.AllowedActions {
		if a == actionType || a == "*" {
			if lease.ResourceScope == "*" || lease.ResourceScope == resource {
				return true
			}
		}
	}
	return false
}

func (e *Evaluator) evaluateRules(actionRules, envRules []policy.Rule, req *models.ActionRequest) (bool, models.ReasonCode) {
	for _, r := range actionRules {
		if r.Deny {
			return false, models.ReasonActionNotAllowed
		}
	}
	for _, r := range envRules {
		if r.Deny {
			if req.Environment == models.EnvironmentProduction {
				return false, models.ReasonProductionDenied
			}
			return false, models.ReasonDenied
		}
	}
	return true, ""
}

func (e *Evaluator) shouldEscalate(actionRules, envRules []policy.Rule, req *models.ActionRequest) bool {
	for _, r := range actionRules {
		if r.ActionType != "*" && r.Escalate {
			return true
		}
	}
	for _, r := range envRules {
		if r.Environment != "*" && r.Escalate {
			return true
		}
	}
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
	return fmt.Sprintf("dec_%s", generateShortID())
}

func generateShortID() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> uint(i*8) & 0xff)
	}
	return hex.EncodeToString(b)[:16]
}

func actionDigest(req *models.ActionRequest) string {
	h := sha256.New()
	h.Write([]byte(string(req.ActionType)))
	h.Write([]byte(req.Resource))
	if req.AgentIdentity != nil {
		h.Write([]byte(req.AgentIdentity.SubjectID))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}
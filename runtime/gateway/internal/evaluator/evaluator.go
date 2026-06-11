package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/observe"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/trust"
)

type RevocationChecker interface {
	IsRevoked(leaseID string) bool
	Touch(leaseID, action, resource string)
}

type Evaluator struct {
	policyStore          *policy.Store
	validator            *identity.Validator
	shieldStore          *trust.ShieldStore
	revocationChecker    RevocationChecker
	driftDetector        *trust.DriftDetector
	degradation          *trust.DegradationModel
	chainDetector        *trust.ChainDetector
	federatedTrustClient FederatedTrustClient
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

// SetDriftDetector configures drift detection for behavioral anomaly detection.
func (e *Evaluator) SetDriftDetector(dd *trust.DriftDetector) {
	e.driftDetector = dd
}

// SetDegradationModel configures trust score degradation and recovery.
func (e *Evaluator) SetDegradationModel(dm *trust.DegradationModel) {
	e.degradation = dm
}

// SetChainDetector configures delegation chain pattern analysis.
func (e *Evaluator) SetChainDetector(cd *trust.ChainDetector) {
	e.chainDetector = cd
}

func (e *Evaluator) SetRevocationChecker(rc RevocationChecker) {
	e.revocationChecker = rc
}

func (e *Evaluator) SetFederatedTrustClient(client FederatedTrustClient) {
	e.federatedTrustClient = client
}

func (e *Evaluator) PolicyVersion() string {
	return e.policyStore.Version()
}

type EvalResult struct {
	Decision         models.Decision
	ReasonCodes      []models.ReasonCode
	TrustScore       float64
	RequiresApproval bool
	PolicyVersion    string
}

type SimResult struct {
	Request           *models.ActionRequest
	Decision         models.Decision
	CurrentDecision  models.Decision
	CandidateDecision models.Decision
	DecisionChanged  bool
	Reason           string
	CurrentReason    string
	CandidateReason  string
	RequiresApproval bool
	TrustScore       float64
	TrustLevel       models.TrustLevel
	PolicyVersion    string
	Passed           bool
}

type BatchSimResult struct {
	Results        []*SimResult
	TotalCount    int
	ChangedCount  int
	UnchangedCount int
	PolicyVersion string
}

type PolicyRuleChange struct {
	ActionType  string
	Environment string
	From        policy.Rule
	To          policy.Rule
}

type PolicyDiff struct {
	AddedRules   []policy.Rule
	RemovedRules []policy.Rule
	ChangedRules []PolicyRuleChange
	FromVersion  string
	ToVersion    string
}

func (e *Evaluator) Evaluate(req *models.ActionRequest) (*models.DecisionResponse, error) {
	ctx, span := observe.StartDecisionSpan(context.Background(), req)
	defer func() {
		if resp, err := e.evaluate(ctx, req); err == nil && resp != nil {
			observe.EndSpan(span, resp.Decision)
			observe.AddSpanEvent(span, "decision.complete", map[string]string{
				"decision_id": resp.DecisionID,
				"trust_score": fmt.Sprintf("%.2f", resp.TrustScore),
			})
		}
	}()
	return e.evaluate(ctx, req)
}

func (e *Evaluator) evaluate(ctx context.Context, req *models.ActionRequest) (*models.DecisionResponse, error) {
	span := observe.SpanFromContext(ctx)

	if errs := req.Validate(); len(errs) > 0 {
		if span != nil {
			observe.AddSpanEvent(span, "validation.failed", map[string]string{"error": errs[0]})
		}
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

	// Validate delegation chain hash integrity and flag invalid chains.
	if decision == "" && req.DelegationChain != nil {
		chainResult := e.validator.ValidateDelegationChain(req.DelegationChain)
		if !chainResult.Valid {
			for range chainResult.Reasons {
				reasons = append(reasons, models.ReasonIdentityInvalid)
			}
			decision = models.DecisionDeny
		}
	}

	if decision == "" && req.CapabilityLease != nil {
		if e.revocationChecker != nil && e.revocationChecker.IsRevoked(req.CapabilityLease.LeaseID) {
			reasons = append(reasons, models.ReasonCapabilityRevoked)
			decision = models.DecisionDeny
		}

		if decision == "" {
			if e.revocationChecker != nil {
				e.revocationChecker.Touch(req.CapabilityLease.LeaseID, string(req.ActionType), req.Resource)
			}
			leaseResult := e.validator.ValidateCapabilityLease(req.CapabilityLease)
			if !leaseResult.Valid {
				for _, reason := range leaseResult.Reasons {
					if strings.Contains(reason, "expiry") {
						reasons = append(reasons, models.ReasonCapabilityExpiry)
					} else if strings.Contains(reason, "signature") {
						reasons = append(reasons, models.ReasonIdentityInvalid)
					} else {
						reasons = append(reasons, models.ReasonCapabilityNotAllowed)
					}
				}
				decision = models.DecisionDeny
			}
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

	// Drift detection: if the agent's recent action pattern deviates from
	// their established baseline, escalate for human review.
	if decision == "" && e.driftDetector != nil && req.AgentIdentity != nil {
		agentID := req.AgentIdentity.SubjectID
		isRisky := trustResult.Score < 0.8 || len(trustResult.AnomalySignals) > 0
		e.driftDetector.RecordAction(agentID, req.ActionType, req.Resource, isRisky)

		drift := e.driftDetector.CheckDrift(agentID)
		if drift.Drifting {
			reasons = append(reasons, models.ReasonAnomalyDetected)
			if decision != models.DecisionDeny {
				decision = models.DecisionEscalate
				requiresApproval = true
			}
		}
	}

	// Delegation chain pattern analysis: detect suspicious patterns and
	// escalate if found.
	if decision == "" && e.chainDetector != nil && req.DelegationChain != nil && req.AgentIdentity != nil {
		e.chainDetector.RecordChain(req.AgentIdentity.SubjectID, req.DelegationChain)
		suspicions := e.chainDetector.DetectSuspiciousPatterns(req.AgentIdentity.SubjectID)
		for _, s := range suspicions {
			if s.Severity == "high" {
				reasons = append(reasons, models.ReasonAnomalyDetected)
				decision = models.DecisionEscalate
				requiresApproval = true
				break
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

	// Trust-dependent policy rules: deny or escalate if the agent's trust
	// score/level falls below rule-specified minimums.
	if decision == models.DecisionAllow {
		for _, r := range actionRules {
			if r.MinTrustScore != nil && trustScore < *r.MinTrustScore {
				reasons = append(reasons, models.ReasonTrustLow)
				decision = models.DecisionDeny
				break
			}
			if r.MinTrustLevel != "" && trustLevelBelow(trustResult.Level, r.MinTrustLevel) {
				reasons = append(reasons, models.ReasonTrustLow)
				decision = models.DecisionDeny
				break
			}
		}
	}

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

	if span != nil {
		observe.AddSpanAttribute(span, "policy_version", policyVersion)
		observe.AddSpanAttribute(span, "trust_score", fmt.Sprintf("%.2f", trustScore))
		observe.AddSpanAttribute(span, "trust_level", string(trustResult.Level))
		observe.AddSpanEvent(span, "evaluation.complete", map[string]string{
			"decision":   string(decision),
			"reasons":    fmt.Sprintf("%v", reasons),
		})
	}

	trustCtx := &models.TrustContext{
		Score:          trustScore,
		Level:          trustResult.Level,
		AnomalySignals: trustResult.AnomalySignals,
		ShieldActive:   trustResult.ShieldActive,
		Restricted:     trustResult.Restricted,
		RiskCount:      trustResult.RiskCount,
		EvaluationTime: time.Now().UTC(),
	}

	summary := buildEvaluationSummary(decision, reasons)

	return &models.DecisionResponse{
		DecisionID:        generateID(),
		Decision:          decision,
		ReasonCodes:       reasons,
		TrustScore:        trustScore,
		TrustLevel:        trustResult.Level,
		RequiresApproval:  requiresApproval,
		ReceiptStub:       receiptStub,
		TrustContext:      trustCtx,
		EvaluationSummary: summary,
	}, nil
}

func buildEvaluationSummary(decision models.Decision, reasons []models.ReasonCode) string {
	has := func(code models.ReasonCode) bool {
		for _, r := range reasons {
			if r == code {
				return true
			}
		}
		return false
	}

	switch decision {
	case models.DecisionAllow:
		if has(models.ReasonPolicyAllow) {
			return "allowed by explicit policy rule"
		}
		return "allowed by default (no matching deny/escalate rule)"
	case models.DecisionDeny:
		if has(models.ReasonProductionDenied) {
			return "denied by production policy rule"
		}
		if has(models.ReasonPolicyDeny) {
			return "denied by explicit policy rule"
		}
		if has(models.ReasonIdentityInvalid) {
			return "denied: invalid or missing agent identity"
		}
		if has(models.ReasonCapabilityNotAllowed) || has(models.ReasonCapabilityExpiry) {
			return "denied: capability validation failed"
		}
		return "denied by policy"
	case models.DecisionEscalate:
		if has(models.ReasonContainmentActive) {
			return "escalated: agent is restricted or contained"
		}
		if has(models.ReasonTrustEscalate) {
			return "escalated: low trust score or anomaly detected"
		}
		if has(models.ReasonPolicyEscalate) {
			return "escalated by explicit policy rule"
		}
		return "escalated: requires approval"
	default:
		return "evaluation incomplete"
	}
}

type RuleOutcome struct {
	Allowed  bool
	Denied   bool
	Escalate bool
	Reason   models.ReasonCode
}

func (e *Evaluator) evaluateRules(actionRules, envRules []policy.Rule, req *models.ActionRequest) RuleOutcome {
	for _, r := range actionRules {
		if r.Deny && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			if req.Environment == models.EnvironmentProduction {
				return RuleOutcome{Denied: true, Reason: models.ReasonProductionDenied}
			}
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}
	for _, r := range envRules {
		if r.Deny && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			if req.Environment == models.EnvironmentProduction {
				return RuleOutcome{Denied: true, Reason: models.ReasonProductionDenied}
			}
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}

	for _, r := range actionRules {
		if r.Allow && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow}
		}
	}
	for _, r := range envRules {
		if r.Allow && r.Environment != "*" && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow}
		}
	}

	for _, r := range actionRules {
		if r.Escalate && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}
	for _, r := range envRules {
		if r.Escalate && r.Environment != "*" && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}

	return RuleOutcome{Allowed: true, Reason: models.ReasonAllowed}
}

func (e *Evaluator) evaluateRulesWithStore(store *policy.Store, req *models.ActionRequest) RuleOutcome {
	actionRules := store.RulesForAction(string(req.ActionType))
	envRules := store.RulesForEnvironment(string(req.Environment))
	return e.evaluateRules(actionRules, envRules, req)
}

func (e *Evaluator) Simulate(req *models.ActionRequest, candidateStore *policy.Store) (*SimResult, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return &SimResult{
			Request:    req,
			Decision:  models.DecisionDeny,
			Reason:    "invalid request: " + errs[0],
			Passed:    false,
		}, nil
	}

	outcome := e.evaluateRulesWithStore(candidateStore, req)
	trustResult := trust.NewEvaluator(e.shieldStore).Evaluate(req)

	var decision models.Decision
	var requiresApproval bool
	var reason string

	if outcome.Denied {
		decision = models.DecisionDeny
		reason = string(outcome.Reason)
	} else if outcome.Escalate || trustResult.ShouldEscalate() {
		decision = models.DecisionEscalate
		requiresApproval = true
		if outcome.Escalate {
			reason = string(outcome.Reason)
		} else {
			reason = string(models.ReasonTrustEscalate)
		}
	} else {
		decision = models.DecisionAllow
		reason = string(outcome.Reason)
	}

	return &SimResult{
		Request:           req,
		Decision:         decision,
		Reason:           reason,
		RequiresApproval:  requiresApproval,
		TrustScore:        trustResult.Score,
		TrustLevel:        trustResult.Level,
		PolicyVersion:    candidateStore.Version(),
		Passed:           true,
	}, nil
}

func (e *Evaluator) SimulateBatch(requests []*models.ActionRequest, candidateStore *policy.Store) *BatchSimResult {
	results := make([]*SimResult, 0, len(requests))
	changedCount := 0

	currentStore := e.policyStore

	for _, req := range requests {
		currentResult, _ := e.Simulate(req, currentStore)
		candidateResult, _ := e.Simulate(req, candidateStore)

		result := &SimResult{
			Request:          req,
			CurrentDecision:  currentResult.Decision,
			CandidateDecision: candidateResult.Decision,
			DecisionChanged:  currentResult.Decision != candidateResult.Decision,
			CurrentReason:    currentResult.Reason,
			CandidateReason:  candidateResult.Reason,
			RequiresApproval: candidateResult.RequiresApproval,
			TrustScore:       candidateResult.TrustScore,
			TrustLevel:       candidateResult.TrustLevel,
			PolicyVersion:    candidateStore.Version(),
			Passed:          true,
		}

		if result.DecisionChanged {
			changedCount++
		}

		results = append(results, result)
	}

	return &BatchSimResult{
		Results:       results,
		TotalCount:    len(requests),
		ChangedCount:  changedCount,
		UnchangedCount: len(requests) - changedCount,
		PolicyVersion: candidateStore.Version(),
	}
}

func (e *Evaluator) ComparePolicies(candidateStore *policy.Store) *PolicyDiff {
	currentRules := e.policyStore.ListRules()
	candidateRules := candidateStore.ListRules()

	currentRuleMap := make(map[string]policy.Rule)
	for _, r := range currentRules {
		key := ruleKey(r.ActionType, r.Environment)
		currentRuleMap[key] = r
	}

	candidateRuleMap := make(map[string]policy.Rule)
	for _, r := range candidateRules {
		key := ruleKey(r.ActionType, r.Environment)
		candidateRuleMap[key] = r
	}

	var added []policy.Rule
	var removed []policy.Rule
	var changed []PolicyRuleChange

	for key, cr := range candidateRuleMap {
		if pr, exists := currentRuleMap[key]; exists {
			if pr.Allow != cr.Allow || pr.Deny != cr.Deny || pr.Escalate != cr.Escalate {
				changed = append(changed, PolicyRuleChange{
					ActionType:  cr.ActionType,
					Environment: cr.Environment,
					From:       pr,
					To:         cr,
				})
			}
		} else {
			added = append(added, cr)
		}
	}

	for key, pr := range currentRuleMap {
		if _, exists := candidateRuleMap[key]; !exists {
			removed = append(removed, pr)
		}
	}

	return &PolicyDiff{
		AddedRules:   added,
		RemovedRules: removed,
		ChangedRules: changed,
		FromVersion:  e.policyStore.Version(),
		ToVersion:    candidateStore.Version(),
	}
}

func ruleKey(actionType, environment string) string {
	return actionType + ":" + environment
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

// trustLevelBelow returns true if actualLevel is below the named minimum.
// Order: none < low < medium < high
func trustLevelBelow(actual models.TrustLevel, minName string) bool {
	order := map[models.TrustLevel]int{
		models.TrustLevelNone:   0,
		models.TrustLevelLow:    1,
		models.TrustLevelMedium: 2,
		models.TrustLevelHigh:   3,
	}
	actualOrd, actualOk := order[actual]
	minOrd, minOk := order[models.TrustLevel(minName)]
	if !actualOk || !minOk {
		return false
	}
	return actualOrd < minOrd
}
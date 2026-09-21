package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/observe"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/replay"
	"ovara.runtime.gateway/internal/revocation"
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
	nonceCache           map[string]time.Time
	delegNonceCache      map[string]time.Time
	nonceSweepAt         time.Time
	nonceMu              sync.Mutex
	// replayStore, when set, replaces both in-memory nonce caches with a
	// durable consume store (P2.1). Unset preserves RC1 semantics exactly.
	replayStore replay.Store
	// revChecker is the P2.3.4 shared revocation boundary — consulted
	// for min_epoch and receipts here, and pushed into the validator
	// for issuer/delegation/lease checks on verified material.
	revChecker revocation.Checker
}

func New(p *policy.Store) *Evaluator {
	return &Evaluator{
		policyStore:     p,
		validator:       identity.NewValidator(),
		shieldStore:     trust.NewShieldStore(),
		nonceCache:      make(map[string]time.Time),
		delegNonceCache: make(map[string]time.Time),
	}
}

func NewWithShield(p *policy.Store, ss *trust.ShieldStore) *Evaluator {
	return &Evaluator{
		policyStore:     p,
		validator:       identity.NewValidator(),
		shieldStore:     ss,
		nonceCache:      make(map[string]time.Time),
		delegNonceCache: make(map[string]time.Time),
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

// SetValidator configures the identity validator used for lease and
// identity checks, e.g. one backed by a trusted-issuer key registry.
func (e *Evaluator) SetValidator(v *identity.Validator) {
	e.validator = v
	if e.revChecker != nil {
		v.SetRevocation(e.revChecker)
	}
}

// SetRevocation installs the shared revocation boundary (P2.3.4) —
// one checker used at evaluation time (issuer, delegation, lease,
// min_epoch) and propagated to whichever validator is in force, so
// ordering of SetValidator/SetRevocation doesn't matter.
func (e *Evaluator) SetRevocation(rc revocation.Checker) {
	e.revChecker = rc
	if e.validator != nil {
		e.validator.SetRevocation(rc)
	}
}

func (e *Evaluator) SetRevocationChecker(rc RevocationChecker) {
	e.revocationChecker = rc
}

func (e *Evaluator) SetFederatedTrustClient(client FederatedTrustClient) {
	e.federatedTrustClient = client
}

// SetReplayStore installs the durable consume store (P2.1). When set,
// request nonces and delegation replay keys consume durably; when nil,
// the process-local RC1 caches apply unchanged.
func (e *Evaluator) SetReplayStore(s replay.Store) {
	e.replayStore = s
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
	Decision          models.Decision
	CurrentDecision   models.Decision
	CandidateDecision models.Decision
	DecisionChanged   bool
	Reason            string
	CurrentReason     string
	CandidateReason   string
	RequiresApproval  bool
	TrustScore        float64
	TrustLevel        models.TrustLevel
	PolicyVersion     string
	Passed            bool
}

type BatchSimResult struct {
	Results        []*SimResult
	TotalCount     int
	ChangedCount   int
	UnchangedCount int
	PolicyVersion  string
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

func (e *Evaluator) Evaluate(req *models.ActionRequest) (resp *models.DecisionResponse, err error) {
	ctx, span := observe.StartDecisionSpan(context.Background(), req)
	defer func() {
		if err == nil && resp != nil {
			observe.EndSpan(span, resp.Decision)
			observe.AddSpanEvent(span, "decision.complete", map[string]string{
				"decision_id": resp.DecisionID,
				"trust_score": fmt.Sprintf("%.2f", resp.TrustScore),
			})
		} else {
			observe.EndSpan(span, models.DecisionDeny)
		}
	}()
	resp, err = e.evaluate(ctx, req)
	return resp, err
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

	// Replay and freshness protection: reject requests outside a tight clock
	// skew and reject any nonce that has already been seen.
	const maxClockSkew = 60 * time.Second
	now := time.Now().UTC()
	if req.IssuedAt.Before(now.Add(-maxClockSkew)) || req.IssuedAt.After(now.Add(maxClockSkew)) {
		return &models.DecisionResponse{
			Decision:    models.DecisionDeny,
			ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
		}, nil
	}
	// P2.3.4 min_epoch: the caller cites the revocation epoch its
	// authorization context requires. A gateway below it — or unable
	// to prove its epoch — cannot satisfy the requirement; deny BEFORE
	// consuming the request nonce so a retry under a fresher view
	// isn't poisoned.
	if req.MinEpoch > 0 {
		if e.revChecker == nil {
			return &models.DecisionResponse{
				Decision:    models.DecisionDeny,
				ReasonCodes: []models.ReasonCode{models.ReasonRevocationUnavailable},
			}, nil
		}
		ep, err := e.revChecker.Epoch()
		if err != nil || ep < req.MinEpoch {
			return &models.DecisionResponse{
				Decision:    models.DecisionDeny,
				ReasonCodes: []models.ReasonCode{models.ReasonRevocationEpoch},
			}, nil
		}
	}
	if e.replayStore != nil {
		switch e.replayStore.Consume(replay.KindRequest, req.Nonce, now.Add(5*time.Minute)) {
		case replay.AlreadyConsumed, replay.StorageFailure:
			// StorageFailure fails closed: replay state cannot be
			// proven, so the request cannot be authorized.
			return &models.DecisionResponse{
				Decision:    models.DecisionDeny,
				ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
			}, nil
		}
	} else {
		e.nonceMu.Lock()
		if seenAt, ok := e.nonceCache[req.Nonce]; ok && now.Sub(seenAt) < 5*time.Minute {
			e.nonceMu.Unlock()
			return &models.DecisionResponse{
				Decision:    models.DecisionDeny,
				ReasonCodes: []models.ReasonCode{models.ReasonActionNotAllowed},
			}, nil
		}
		e.nonceCache[req.Nonce] = now
		// ponytail: amortized sweep once a minute; expired entries are denied anyway,
		// this only bounds memory. A TTL map would be the upgrade if needed.
		if now.After(e.nonceSweepAt) {
			for n, seenAt := range e.nonceCache {
				if now.Sub(seenAt) >= 5*time.Minute {
					delete(e.nonceCache, n)
				}
			}
			e.nonceSweepAt = now.Add(time.Minute)
		}
		e.nonceMu.Unlock()
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

	// Validate the delegation chain: signatures against the trusted
	// issuer registry, chain linkage, non-amplification, expiry,
	// audience, final-subject binding to the authenticated principal,
	// and nonce replay.
	if decision == "" && req.DelegationChain != nil {
		subject := ""
		if req.AgentIdentity != nil {
			subject = req.AgentIdentity.SubjectID
		}
		chainResult := e.validator.ValidateDelegationChain(req.DelegationChain, subject, e.markDelegationNonce)
		if !chainResult.Valid {
			for range chainResult.Reasons {
				reasons = append(reasons, models.ReasonIdentityInvalid)
			}
			decision = models.DecisionDeny
		} else {
			// CAPABILITY ENFORCEMENT: delegation is a capability, not an
			// attestation — the request must fall inside the terminal
			// hop's effective scope. A valid chain delegating "shell"
			// must not ride a "deploy" request; a chain scoped to
			// https://api.example.com/* must not authorize another host.
			// The chain narrows the request context; it never lifts
			// policy (policy still decides below).
			capActions, capScope := identity.TerminalCapability(req.DelegationChain)
			if !identity.ActionInScope(string(req.ActionType), capActions) ||
				!identity.ScopeMatches(capScope, req.Resource) {
				reasons = append(reasons, models.ReasonDelegationScope)
				decision = models.DecisionDeny
			}
		}
	}

	// Lease validation only runs when a lease is PRESENT in the request.
	// A nil lease is not an error: leases are optional for policy-level
	// checks, and lease-less requests are decided on policy rules plus
	// agent identity alone. However, a lease that is present but unsigned,
	// tampered, expired, revoked, or out of scope always denies below — a
	// caller cannot weaken a decision by attaching a garbage lease.
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

		// SUBJECT BINDING: the lease must name the authenticated
		// principal (the normalized agent_identity.subject_id). A valid
		// lease minted for another subject is misuse — deny. A lease
		// presented with no bindable principal can't authorize either.
		if decision == "" && (req.AgentIdentity == nil ||
			req.CapabilityLease.Subject != req.AgentIdentity.SubjectID) {
			reasons = append(reasons, models.ReasonCapabilityNotAllowed)
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
		} else if outcome.LeaseRequired && req.CapabilityLease == nil {
			// require_lease: the matched rule allows only with a valid
			// principal-bound lease — escalate so a human can approve
			// rather than allowing an unleased privileged action.
			reasons = append(reasons, models.ReasonLeaseRequired)
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
			"decision": string(decision),
			"reasons":  fmt.Sprintf("%v", reasons),
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
	// LeaseRequired is set when the matched rule carries require_lease:
	// an allow outcome without a valid lease escalates instead.
	LeaseRequired bool
}

func (e *Evaluator) evaluateRules(actionRules, envRules []policy.Rule, req *models.ActionRequest) RuleOutcome {
	// A rule only applies when its resource pattern matches the request
	// resource; empty patterns match everything (pre-resource rules keep
	// their semantics).
	res := func(r policy.Rule) bool { return policy.MatchResource(r.Resource, req.Resource) }

	for _, r := range actionRules {
		if res(r) && r.Deny && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			if req.Environment == models.EnvironmentProduction {
				return RuleOutcome{Denied: true, Reason: models.ReasonProductionDenied}
			}
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}
	for _, r := range envRules {
		if res(r) && r.Deny && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			if req.Environment == models.EnvironmentProduction {
				return RuleOutcome{Denied: true, Reason: models.ReasonProductionDenied}
			}
			return RuleOutcome{Denied: true, Reason: models.ReasonPolicyDeny}
		}
	}

	for _, r := range actionRules {
		if res(r) && r.Allow && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow, LeaseRequired: r.RequireLease}
		}
	}
	for _, r := range envRules {
		if res(r) && r.Allow && r.Environment != "*" && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			return RuleOutcome{Allowed: true, Reason: models.ReasonPolicyAllow, LeaseRequired: r.RequireLease}
		}
	}

	for _, r := range actionRules {
		if res(r) && r.Escalate && (r.Environment == "*" || r.Environment == string(req.Environment)) {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}
	for _, r := range envRules {
		if res(r) && r.Escalate && r.Environment != "*" && (r.ActionType == "*" || r.ActionType == string(req.ActionType)) {
			return RuleOutcome{Escalate: true, Reason: models.ReasonPolicyEscalate}
		}
	}

	// Default decision is escalate: requests that match no explicit rule
	// require approval rather than being silently allowed.
	return RuleOutcome{Escalate: true, Reason: models.ReasonEscalate}
}

// markDelegationNonce consumes the chain's replay identity, namespaced
// SEPARATE from request nonces: request nonces are client-chosen
// strings, so any shared-map prefix ("deleg:"+nonce) could be forged as
// a request nonce to poison a legitimate delegation. With a
// durable replay store the record lives until expiresAt — the chain's
// effective expiry — so a capability cannot be re-presented within its
// lifetime, across restarts. Without a store the RC1 process-local
// 5-minute window applies unchanged.
func (e *Evaluator) markDelegationNonce(replayKey string, expiresAt time.Time) identity.NonceMark {
	if e.replayStore != nil {
		switch e.replayStore.Consume(replay.KindDelegation, replayKey, expiresAt) {
		case replay.FirstConsume:
			return identity.NonceMarkFirst
		case replay.AlreadyConsumed:
			return identity.NonceMarkSeen
		default:
			return identity.NonceMarkFailed
		}
	}
	e.nonceMu.Lock()
	defer e.nonceMu.Unlock()
	if seenAt, ok := e.delegNonceCache[replayKey]; ok && time.Now().Sub(seenAt) < 5*time.Minute {
		return identity.NonceMarkSeen
	}
	e.delegNonceCache[replayKey] = time.Now()
	// piggyback sweep so the map can't grow without bound
	if e.nonceSweepAt.Before(time.Now()) {
		for k, seenAt := range e.delegNonceCache {
			if time.Since(seenAt) > 10*time.Minute {
				delete(e.delegNonceCache, k)
			}
		}
	}
	return identity.NonceMarkFirst
}

func (e *Evaluator) evaluateRulesWithStore(store *policy.Store, req *models.ActionRequest) RuleOutcome {
	actionRules := store.RulesForAction(string(req.ActionType))
	envRules := store.RulesForEnvironment(string(req.Environment))
	return e.evaluateRules(actionRules, envRules, req)
}

func (e *Evaluator) Simulate(req *models.ActionRequest, candidateStore *policy.Store) (*SimResult, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return &SimResult{
			Request:  req,
			Decision: models.DecisionDeny,
			Reason:   "invalid request: " + errs[0],
			Passed:   false,
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
		Request:          req,
		Decision:         decision,
		Reason:           reason,
		RequiresApproval: requiresApproval,
		TrustScore:       trustResult.Score,
		TrustLevel:       trustResult.Level,
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
			Request:           req,
			CurrentDecision:   currentResult.Decision,
			CandidateDecision: candidateResult.Decision,
			DecisionChanged:   currentResult.Decision != candidateResult.Decision,
			CurrentReason:     currentResult.Reason,
			CandidateReason:   candidateResult.Reason,
			RequiresApproval:  candidateResult.RequiresApproval,
			TrustScore:        candidateResult.TrustScore,
			TrustLevel:        candidateResult.TrustLevel,
			PolicyVersion:     candidateStore.Version(),
			Passed:            true,
		}

		if result.DecisionChanged {
			changedCount++
		}

		results = append(results, result)
	}

	return &BatchSimResult{
		Results:        results,
		TotalCount:     len(requests),
		ChangedCount:   changedCount,
		UnchangedCount: len(requests) - changedCount,
		PolicyVersion:  candidateStore.Version(),
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
					From:        pr,
					To:          cr,
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
	stub := &models.ReceiptStub{
		ReceiptID:         generateID(),
		ActionDigest:      actionDigest(req),
		ActionType:        string(req.ActionType),
		Resource:          req.Resource,
		PolicyVersion:     policyVersion,
		TrustContextScore: trustScore,
		IssuedAt:          time.Now().UTC(),
	}
	// Bind the revocation epoch the decision was made against (P2.3.4)
	// — informational: a later revocation never rewrites the receipt,
	// the epoch records WHICH authority view produced it.
	if e.revChecker != nil {
		if ep, err := e.revChecker.Epoch(); err == nil {
			stub.TrustEpoch = ep
		}
	}
	return stub
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

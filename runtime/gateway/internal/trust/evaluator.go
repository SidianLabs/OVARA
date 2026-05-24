package trust

import (
	"strings"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type Evaluator struct {
	shieldStore *ShieldStore
}

func NewEvaluator(shieldStore *ShieldStore) *Evaluator {
	return &Evaluator{shieldStore: shieldStore}
}

type TrustResult struct {
	Score         float64
	Level         models.TrustLevel
	AnomalySignals []models.AnomalySignal
	ShieldActive  bool
	Restricted    bool
	RiskCount     int
}

func (e *Evaluator) Evaluate(req *models.ActionRequest) *TrustResult {
	result := &TrustResult{
		Score: 1.0,
		Level: models.TrustLevelHigh,
	}

	agentID := ""
	if req.AgentIdentity != nil {
		agentID = req.AgentIdentity.SubjectID
	}

	if agentID != "" && e.shieldStore != nil {
		restriction := e.shieldStore.GetRestriction(agentID)
		if restriction != nil {
			result.Restricted = true
			result.Score -= 0.4
			result.AnomalySignals = append(result.AnomalySignals, models.AnomalySignal{
				Code:     string(models.ReasonContainmentActive),
				Pattern:  "agent_restricted",
				Severity: "high",
			})
		}

		riskCount := e.shieldStore.GetRiskCount(agentID)
		result.RiskCount = riskCount
		if riskCount > 0 {
			result.Score -= float64(riskCount) * 0.05
			if riskCount >= 3 {
				result.AnomalySignals = append(result.AnomalySignals, models.AnomalySignal{
					Code:     string(models.ReasonRepeatedRisk),
					Pattern:  "repeated_risk_behavior",
					Severity: "medium",
				})
			}
		}
	}

	if e.shieldStore != nil && agentID != "" {
		lastDecision := e.shieldStore.GetLastDecision(agentID)
		if lastDecision != "" && time.Since(e.shieldStore.GetLastDecisionTime(agentID)) < 30*time.Second {
			if lastDecision == string(models.DecisionEscalate) || lastDecision == string(models.DecisionDeny) {
				result.Score -= 0.1
			}
		}
	}

	shellSignals := e.evaluateShellPatterns(req)
	for _, s := range shellSignals {
		result.AnomalySignals = append(result.AnomalySignals, s)
		result.Score -= 0.15
	}

	gitSignals := e.evaluateGitPatterns(req)
	for _, s := range gitSignals {
		result.AnomalySignals = append(result.AnomalySignals, s)
		result.Score -= 0.15
	}

	prodSignal := e.evaluateProductionTarget(req)
	if prodSignal.Code != "" {
		result.AnomalySignals = append(result.AnomalySignals, prodSignal)
		result.Score -= 0.2
	}

	leaseSignal := e.evaluateLeaseScope(req)
	if leaseSignal.Code != "" {
		result.AnomalySignals = append(result.AnomalySignals, leaseSignal)
		result.Score -= 0.1
	}

	delegationSignal := e.evaluateDelegationDepth(req)
	if delegationSignal.Code != "" {
		result.AnomalySignals = append(result.AnomalySignals, delegationSignal)
		result.Score -= 0.1
	}

	if result.Score < 0 {
		result.Score = 0
	}
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	result.Level = scoreToLevel(result.Score)
	result.ShieldActive = result.Score < 0.6

	return result
}

func (e *Evaluator) evaluateShellPatterns(req *models.ActionRequest) []models.AnomalySignal {
	var signals []models.AnomalySignal
	if req.ActionType != models.ActionTypeShell {
		return signals
	}

	resource := req.Resource
	risky := []string{
		"rm -rf", "mkfs", "dd if=", ":(){:|:&};:", "curl |sh", "wget |sh",
		"chmod -R 777", "chown -R", "sudo su", "passwd root",
		"killall", "pkill -9", "reboot", "shutdown",
		"> /etc/", "> /var/", "/dev/sd", "nc -e", "bash -i",
	}

	for _, pattern := range risky {
		if strings.Contains(resource, pattern) {
			signals = append(signals, models.AnomalySignal{
				Code:     string(models.ReasonRiskyShellPattern),
				Pattern:  pattern,
				Severity: "high",
			})
			break
		}
	}

	return signals
}

func (e *Evaluator) evaluateGitPatterns(req *models.ActionRequest) []models.AnomalySignal {
	var signals []models.AnomalySignal

	riskyGit := map[models.ActionType]string{
		models.ActionTypeGitForcePush:     "--force",
		models.ActionTypeGitPush:         "force_push_candidate",
		models.ActionTypeGitHubDelete:     "branch_deletion",
	}

	if pattern, ok := riskyGit[req.ActionType]; ok {
		signals = append(signals, models.AnomalySignal{
			Code:     string(models.ReasonRiskyGitPattern),
			Pattern:  pattern,
			Severity: "medium",
		})
	}

	return signals
}

func (e *Evaluator) evaluateProductionTarget(req *models.ActionRequest) models.AnomalySignal {
	if req.Environment == models.EnvironmentProduction {
		return models.AnomalySignal{
			Code:     string(models.ReasonProductionTarget),
			Pattern:  "production_environment",
			Severity: "high",
		}
	}
	return models.AnomalySignal{}
}

func (e *Evaluator) evaluateLeaseScope(req *models.ActionRequest) models.AnomalySignal {
	if req.CapabilityLease == nil {
		return models.AnomalySignal{}
	}

	if req.CapabilityLease.ResourceScope == "*" && req.ActionType == models.ActionTypeShell {
		return models.AnomalySignal{
			Code:     string(models.ReasonWeakLeaseScope),
			Pattern:  "wildcard_scope_with_shell",
			Severity: "medium",
		}
	}

	return models.AnomalySignal{}
}

func (e *Evaluator) evaluateDelegationDepth(req *models.ActionRequest) models.AnomalySignal {
	if req.DelegationChain != nil {
		if req.DelegationChain.Depth > 3 {
			return models.AnomalySignal{
				Code:     "excessive_delegation_depth",
				Pattern:  "depth_exceeds_3",
				Severity: "medium",
			}
		}
	}
	return models.AnomalySignal{}
}

func scoreToLevel(score float64) models.TrustLevel {
	switch {
	case score >= 0.8:
		return models.TrustLevelHigh
	case score >= 0.5:
		return models.TrustLevelMedium
	case score > 0:
		return models.TrustLevelLow
	default:
		return models.TrustLevelNone
	}
}

func (r *TrustResult) ShouldEscalate() bool {
	return r.Level == models.TrustLevelLow || r.Level == models.TrustLevelNone || r.Score < 0.5
}

func (r *TrustResult) IsRestricted() bool {
	return r.Restricted || r.Score < 0.3
}

func AddAnomalyReasons(result *TrustResult, reasons []models.ReasonCode) []models.ReasonCode {
	for _, signal := range result.AnomalySignals {
		reasons = append(reasons, models.ReasonCode(signal.Code))
	}
	if result.Restricted {
		reasons = append(reasons, models.ReasonContainmentActive)
	}
	return reasons
}
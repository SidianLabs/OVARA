package models

import (
	"encoding/json"
	"testing"
)

func TestActionRequest_Validate_Valid(t *testing.T) {
	req := ActionRequest{
		ActionType:  ActionTypeShell,
		Resource:    "shell:ls",
		Environment: EnvironmentLocal,
	}
	errs := req.Validate()
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestActionRequest_Validate_MissingActionType(t *testing.T) {
	req := ActionRequest{
		Resource:    "shell:ls",
		Environment: EnvironmentLocal,
	}
	errs := req.Validate()
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if errs[0] != "action_type is required" {
		t.Errorf("expected 'action_type is required', got %s", errs[0])
	}
}

func TestActionRequest_Validate_MissingResource(t *testing.T) {
	req := ActionRequest{
		ActionType:  ActionTypeShell,
		Environment: EnvironmentLocal,
	}
	errs := req.Validate()
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if errs[0] != "resource is required" {
		t.Errorf("expected 'resource is required', got %s", errs[0])
	}
}

func TestActionRequest_Validate_MissingEnvironment(t *testing.T) {
	req := ActionRequest{
		ActionType: ActionTypeShell,
		Resource:   "shell:ls",
	}
	errs := req.Validate()
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if errs[0] != "environment is required" {
		t.Errorf("expected 'environment is required', got %s", errs[0])
	}
}

func TestActionRequest_Validate_MultipleErrors(t *testing.T) {
	req := ActionRequest{}
	errs := req.Validate()
	if len(errs) != 3 {
		t.Errorf("expected 3 errors, got %d", len(errs))
	}
}

func TestActionType_Constants(t *testing.T) {
	types := []ActionType{
		ActionTypeShell,
		ActionTypeExec,
		ActionTypeGitPush,
		ActionTypeGitPull,
		ActionTypeGitFetch,
		ActionTypeGitCheckout,
		ActionTypeGitForcePush,
		ActionTypeGitHubPush,
		ActionTypeGitHubPR,
		ActionTypeGitHubMerge,
		ActionTypeGitHubDelete,
		ActionTypeCIDeploy,
		ActionTypeCIBuildTrigger,
		ActionTypeCIApproval,
	}
	expected := []string{
		"shell", "exec", "git.push", "git.pull", "git.fetch", "git.checkout",
		"git.force_push", "github.push", "github.pr", "github.merge",
		"github.delete_branch", "ci.deploy", "ci.build_trigger", "ci.approval",
	}
	for i, at := range types {
		if string(at) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], at)
		}
	}
}

func TestEnvironment_Constants(t *testing.T) {
	envs := []Environment{
		EnvironmentLocal,
		EnvironmentDev,
		EnvironmentStaging,
		EnvironmentProduction,
	}
	expected := []string{"local", "dev", "staging", "production"}
	for i, env := range envs {
		if string(env) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], env)
		}
	}
}

func TestDecision_Constants(t *testing.T) {
	decisions := []Decision{
		DecisionAllow,
		DecisionDeny,
		DecisionEscalate,
	}
	expected := []string{"allow", "deny", "escalate"}
	for i, d := range decisions {
		if string(d) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], d)
		}
	}
}

func TestTrustLevel_Constants(t *testing.T) {
	levels := []TrustLevel{
		TrustLevelHigh,
		TrustLevelMedium,
		TrustLevelLow,
		TrustLevelNone,
	}
	expected := []string{"high", "medium", "low", "none"}
	for i, l := range levels {
		if string(l) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], l)
		}
	}
}

func TestActionRequest_JSONMarshal(t *testing.T) {
	req := ActionRequest{
		ActionType:  ActionTypeShell,
		Resource:    "shell:ls",
		Environment: EnvironmentLocal,
		Metadata:    json.RawMessage(`{"key":"value"}`),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var decoded ActionRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if decoded.ActionType != ActionTypeShell {
		t.Errorf("expected shell, got %s", decoded.ActionType)
	}
}

func TestCapabilityLease_JSONRoundTrip(t *testing.T) {
	lease := CapabilityLease{
		LeaseID:        "lease-001",
		Issuer:         "issuer-001",
		Subject:        "subject-001",
		AllowedActions: []string{"shell", "exec"},
		ResourceScope:  "shell:*",
		DelegationDepth: 1,
	}
	data, err := json.Marshal(lease)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var decoded CapabilityLease
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if decoded.LeaseID != "lease-001" {
		t.Errorf("expected lease-001, got %s", decoded.LeaseID)
	}
	if len(decoded.AllowedActions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(decoded.AllowedActions))
	}
}

func TestDelegationChain_JSONRoundTrip(t *testing.T) {
	chain := DelegationChain{
		Authorities: []Authority{
			{Issuer: "issuer-001", SubjectID: "sub-001"},
			{Issuer: "issuer-002", SubjectID: "sub-002"},
		},
		ChainHash: "abc123",
		Depth:     2,
	}
	data, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var decoded DelegationChain
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if decoded.Depth != 2 {
		t.Errorf("expected depth 2, got %d", decoded.Depth)
	}
	if len(decoded.Authorities) != 2 {
		t.Errorf("expected 2 authorities, got %d", len(decoded.Authorities))
	}
}
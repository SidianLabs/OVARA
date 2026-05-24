package models

import (
	"encoding/json"
	"time"
)

type ActionType string

const (
	ActionTypeShell           ActionType = "shell"
	ActionTypeGitPush         ActionType = "git.push"
	ActionTypeGitPull         ActionType = "git.pull"
	ActionTypeGitForcePush    ActionType = "git.force_push"
	ActionTypeGitHubPush      ActionType = "github.push"
	ActionTypeGitHubPR        ActionType = "github.pr"
	ActionTypeGitHubMerge     ActionType = "github.merge"
	ActionTypeGitHubDelete    ActionType = "github.delete_branch"
	ActionTypeCIDeploy        ActionType = "ci.deploy"
	ActionTypeCIBuildTrigger  ActionType = "ci.build_trigger"
	ActionTypeCIApproval      ActionType = "ci.approval"
)

type Environment string

const (
	EnvironmentLocal     Environment = "local"
	EnvironmentDev       Environment = "dev"
	EnvironmentStaging  Environment = "staging"
	EnvironmentProduction Environment = "production"
)

type ActionRequest struct {
	ActionType      ActionType       `json:"action_type"`
	Resource        string           `json:"resource"`
	AgentIdentity   *AgentIdentity   `json:"agent_identity,omitempty"`
	CapabilityLease *CapabilityLease `json:"capability_lease,omitempty"`
	DelegationChain *DelegationChain `json:"delegation_chain,omitempty"`
	Environment     Environment      `json:"environment"`
	Metadata        json.RawMessage  `json:"metadata,omitempty"`
}

type AgentIdentity struct {
	Issuer    string `json:"issuer"`
	SubjectID string `json:"subject_id"`
	Owner     string `json:"owner,omitempty"`
	Lifecycle  string `json:"lifecycle,omitempty"`
	VerifyKey string `json:"verify_key,omitempty"`
}

type CapabilityLease struct {
	LeaseID         string    `json:"lease_id"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	AllowedActions  []string  `json:"allowed_actions"`
	ResourceScope   string    `json:"resource_scope"`
	Expiry          time.Time `json:"expiry"`
	DelegationDepth int       `json:"delegation_depth"`
	RevocationHandle string   `json:"revocation_handle,omitempty"`
}

type DelegationChain struct {
	Authorities []Authority `json:"authorities"`
	ChainHash   string      `json:"chain_hash,omitempty"`
	Depth       int         `json:"depth"`
}

type Authority struct {
	Issuer    string `json:"issuer"`
	SubjectID string `json:"subject_id"`
	DelegatedAt time.Time `json:"delegated_at,omitempty"`
}

func (r ActionRequest) Validate() []string {
	var errs []string
	if r.ActionType == "" {
		errs = append(errs, "action_type is required")
	}
	if r.Resource == "" {
		errs = append(errs, "resource is required")
	}
	if r.Environment == "" {
		errs = append(errs, "environment is required")
	}
	return errs
}
package models

import (
	"encoding/json"
	"time"
)

type ActionType string

const (
	ActionTypeShell          ActionType = "shell"
	ActionTypeExec           ActionType = "exec"
	ActionTypeGitPush        ActionType = "git.push"
	ActionTypeGitPull        ActionType = "git.pull"
	ActionTypeGitFetch       ActionType = "git.fetch"
	ActionTypeGitCheckout    ActionType = "git.checkout"
	ActionTypeGitForcePush   ActionType = "git.force_push"
	ActionTypeGitHubPush     ActionType = "github.push"
	ActionTypeGitHubPR       ActionType = "github.pr"
	ActionTypeGitHubMerge    ActionType = "github.merge"
	ActionTypeGitHubDelete   ActionType = "github.delete_branch"
	ActionTypeCIDeploy       ActionType = "ci.deploy"
	ActionTypeCIBuildTrigger ActionType = "ci.build_trigger"
	ActionTypeCIApproval     ActionType = "ci.approval"
)

type Environment string

const (
	EnvironmentLocal      Environment = "local"
	EnvironmentDev        Environment = "dev"
	EnvironmentStaging    Environment = "staging"
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
	Nonce           string           `json:"nonce"`
	IssuedAt        time.Time        `json:"issued_at"`
	// MinEpoch (P2.3.4) is the caller's minimum acceptable revocation
	// epoch — "authorize only if the revocation view is at least this
	// fresh". A gateway whose epoch is below it (or unknowable) denies;
	// stale revocation state must never silently authorize. 0 = unset.
	MinEpoch uint64 `json:"min_epoch,omitempty"`
}

type AgentIdentity struct {
	Issuer    string `json:"issuer"`
	SubjectID string `json:"subject_id"`
	Owner     string `json:"owner,omitempty"`
	Lifecycle string `json:"lifecycle,omitempty"`
	VerifyKey string `json:"verify_key,omitempty"`
}

type CapabilityLease struct {
	LeaseID          string    `json:"lease_id"`
	Issuer           string    `json:"issuer"`
	Subject          string    `json:"subject"`
	AllowedActions   []string  `json:"allowed_actions"`
	ResourceScope    string    `json:"resource_scope"`
	Expiry           time.Time `json:"expiry"`
	DelegationDepth  int       `json:"delegation_depth"`
	IssuedAt         time.Time `json:"issued_at,omitempty"`
	Audience         string    `json:"audience,omitempty"`
	RevocationHandle string    `json:"revocation_handle,omitempty"`
	Signature        []byte    `json:"signature,omitempty"`
	VerifyKey        string    `json:"verify_key,omitempty"`
}

type DelegationChain struct {
	Authorities []Authority `json:"authorities"`
	ChainHash   string      `json:"chain_hash,omitempty"`
	Depth       int         `json:"depth"`
}

// Authority is one signed delegation hop: issuer (a trust-root issuer id
// for the root hop, or the previous hop's subject for subsequent hops)
// grants subject_id a subset of its own authority. Privilege is
// non-amplifying: each hop's scope must be a subset of its parent's.
type Authority struct {
	// Issuer is the delegating party. Root hop: an id present in the
	// gateway's trusted_issuers registry. Later hops: the previous hop's
	// SubjectID — the delegatee exercising its delegated authority.
	Issuer    string `json:"issuer"`
	SubjectID string `json:"subject_id"`
	// Actions scopes the hop to action types ("" or "*" = inherit parent
	// scope; a child may only narrow, never widen).
	Actions []string `json:"actions,omitempty"`
	// ResourceScope is a glob restricting delegated resources
	// (""/"*" = inherit; may only narrow).
	ResourceScope string    `json:"resource_scope,omitempty"`
	Audience      string    `json:"audience,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Nonce         string    `json:"nonce,omitempty"`
	DelegatedAt   time.Time `json:"delegated_at,omitempty"`
	// Signature is ed25519 over the canonical hop payload including the
	// previous hop's signature (chain linkage). Caller-minted chains are
	// worthless: only keys in the issuer registry verify.
	Signature []byte `json:"signature,omitempty"`
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
	if r.Nonce == "" {
		errs = append(errs, "nonce is required")
	}
	if r.IssuedAt.IsZero() {
		errs = append(errs, "issued_at is required")
	}
	return errs
}

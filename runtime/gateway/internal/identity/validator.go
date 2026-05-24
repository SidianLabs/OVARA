package identity

import (
	"fmt"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type ValidationResult struct {
	Valid   bool
	Reasons []string
}

func (v *ValidationResult) Add(reason string) {
	v.Valid = false
	v.Reasons = append(v.Reasons, reason)
}

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateAgentIdentity(identity *models.AgentIdentity) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if identity == nil {
		result.Add("agent_identity is required")
		return result
	}

	if strings.TrimSpace(identity.Issuer) == "" {
		result.Add("agent_identity.issuer is required")
	}
	if strings.TrimSpace(identity.SubjectID) == "" {
		result.Add("agent_identity.subject_id is required")
	}
	if len(identity.SubjectID) > 256 {
		result.Add("agent_identity.subject_id exceeds max length")
	}
	if len(identity.Issuer) > 256 {
		result.Add("agent_identity.issuer exceeds max length")
	}

	return result
}

func (v *Validator) ValidateCapabilityLease(lease *models.CapabilityLease) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if lease == nil {
		result.Add("capability_lease is required")
		return result
	}

	if strings.TrimSpace(lease.LeaseID) == "" {
		result.Add("capability_lease.lease_id is required")
	}
	if strings.TrimSpace(lease.Issuer) == "" {
		result.Add("capability_lease.issuer is required")
	}
	if strings.TrimSpace(lease.Subject) == "" {
		result.Add("capability_lease.subject is required")
	}
	if len(lease.AllowedActions) == 0 {
		result.Add("capability_lease.allowed_actions is required and must not be empty")
	}
	for _, action := range lease.AllowedActions {
		if strings.TrimSpace(action) == "" {
			result.Add("capability_lease.allowed_actions contains empty string")
			break
		}
	}
	if strings.TrimSpace(lease.ResourceScope) == "" {
		result.Add("capability_lease.resource_scope is required")
	}

	if lease.Expiry.IsZero() {
		result.Add("capability_lease.expiry is required")
	} else if lease.Expiry.Before(time.Now()) {
		result.Add("capability_lease.expiry is in the past")
	}

	if lease.DelegationDepth < 0 {
		result.Add("capability_lease.delegation_depth must be non-negative")
	}

	return result
}

func (v *Validator) ValidateCapabilityLeaseScope(lease *models.CapabilityLease, actionType, resource string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if lease == nil {
		return result
	}

	actionAllowed := false
	for _, a := range lease.AllowedActions {
		if a == actionType || a == "*" {
			actionAllowed = true
			break
		}
	}
	if !actionAllowed {
		result.Add(fmt.Sprintf("action %q is not in capability_lease.allowed_actions", actionType))
	}

	if lease.ResourceScope != "*" && lease.ResourceScope != resource {
		result.Add(fmt.Sprintf("resource %q is not covered by capability_lease.scope %q", resource, lease.ResourceScope))
	}

	return result
}

func (v *Validator) ValidateDelegationChain(chain *models.DelegationChain) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if chain == nil {
		return result
	}

	if len(chain.Authorities) == 0 {
		result.Add("delegation_chain.authorities is required and must not be empty")
	}

	for i, auth := range chain.Authorities {
		if strings.TrimSpace(auth.Issuer) == "" {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].issuer is required", i))
		}
		if strings.TrimSpace(auth.SubjectID) == "" {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].subject_id is required", i))
		}
	}

	return result
}

func (v *Validator) ValidateAll(req *models.ActionRequest) *ValidationResult {
	result := &ValidationResult{Valid: true}

	identityResult := v.ValidateAgentIdentity(req.AgentIdentity)
	if !identityResult.Valid {
		for _, r := range identityResult.Reasons {
			result.Add(r)
		}
	}

	leaseResult := v.ValidateCapabilityLease(req.CapabilityLease)
	if !leaseResult.Valid {
		for _, r := range leaseResult.Reasons {
			result.Add(r)
		}
	}

	return result
}
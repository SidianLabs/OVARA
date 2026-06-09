package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

	if len(lease.Signature) > 0 {
		if !v.verifyLeaseSignature(lease) {
			result.Add("capability_lease.signature verification failed")
		}
	}

	return result
}

func (v *Validator) verifyLeaseSignature(lease *models.CapabilityLease) bool {
	if len(lease.Signature) == 0 {
		return true
	}
	if lease.VerifyKey == "" {
		return false
	}
	verifyKey, err := hex.DecodeString(lease.VerifyKey)
	if err != nil || len(verifyKey) != ed25519.PublicKeySize {
		return false
	}
	// Payload format must match ovara.identity module:
	// LeaseID|Issuer|Subject|[AllowedActions]|ResourceScope|ExpiryUnix|DelegationDepth|IssuedAtUnix
	payload := fmt.Sprintf("%s|%s|%s|%v|%s|%d|%d|%d",
		lease.LeaseID, lease.Issuer, lease.Subject, lease.AllowedActions,
		lease.ResourceScope, lease.Expiry.Unix(), lease.DelegationDepth, lease.IssuedAt.Unix(),
	)
	return ed25519.Verify(verifyKey, []byte(payload), lease.Signature)
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

	// Verify chain hash integrity if present.
	if chain.ChainHash != "" && !v.verifyChainHash(chain) {
		result.Add("delegation_chain.chain_hash verification failed")
	}

	return result
}

// verifyChainHash recomputes the chain hash and compares it to the stored hash.
// The hash algorithm matches ovara.identity.DelegationChain.computeHash():
//
//	sha256("depth|Issuer|SubjectID|DelegatedAtUnix|" repeated per authority)
func (v *Validator) verifyChainHash(chain *models.DelegationChain) bool {
	if chain.ChainHash == "" {
		return true
	}
	payload := fmt.Sprintf("%d|", len(chain.Authorities))
	for _, a := range chain.Authorities {
		payload += fmt.Sprintf("%s|%s|%d|", a.Issuer, a.SubjectID, a.DelegatedAt.Unix())
	}
	computed := hex.EncodeToString(sha256Hash([]byte(payload)))
	return hmacEqual(chain.ChainHash, computed)
}

// sha256Hash returns a SHA-256 hash of the input.
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// hmacEqual performs a constant-time comparison to prevent timing attacks.
func hmacEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// validateDelegationChainHash is a convenience function for checking chain integrity.
func (v *Validator) validateDelegationChainHash(chain *models.DelegationChain) bool {
	return chain != nil && chain.ChainHash != "" && v.verifyChainHash(chain)
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
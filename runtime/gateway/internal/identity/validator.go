package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/revocation"
)

type ValidationResult struct {
	Valid   bool
	Reasons []string
}

func (v *ValidationResult) Add(reason string) {
	v.Valid = false
	v.Reasons = append(v.Reasons, reason)
}

type Validator struct {
	// trustedKeys maps issuer ID to the ed25519 public key authorized to
	// sign capability leases for that issuer. When empty, signed leases
	// fail closed: there is no trust anchor to verify against.
	trustedKeys map[string][]byte
	// expectedAudience is this gateway's identity; when set, a lease
	// naming a different audience is invalid (cross-gateway replay).
	expectedAudience string
	// revocation is the P2.3.4 shared revocation boundary. When set,
	// issuer/delegation/lease checks consult it on cryptographically
	// verified material — a storage error is UNKNOWN and fails closed.
	revocation revocation.Checker
}

// SetExpectedAudience binds lease validation to a gateway identity.
func (v *Validator) SetExpectedAudience(aud string) { v.expectedAudience = aud }

// SetRevocation installs the shared revocation boundary (P2.3.4).
// Must be called before concurrent use.
func (v *Validator) SetRevocation(rc revocation.Checker) { v.revocation = rc }

func NewValidator() *Validator {
	return &Validator{trustedKeys: map[string][]byte{}}
}

// NewValidatorWithTrustedKeys returns a Validator that verifies lease
// signatures against the registry of trusted issuer keys (issuer ID ->
// ed25519 public key bytes).
func NewValidatorWithTrustedKeys(trustedKeys map[string][]byte) *Validator {
	if trustedKeys == nil {
		trustedKeys = map[string][]byte{}
	}
	return &Validator{trustedKeys: trustedKeys}
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

	if len(lease.Signature) == 0 {
		result.Add("capability_lease.signature is required")
	} else if !v.verifyLeaseSignature(lease) {
		result.Add("capability_lease.signature verification failed")
	} else if v.revocation != nil {
		// Revocation is consulted only on cryptographically verified
		// material (signature → issuer trust → revocation, per §7).
		// Both the lease's issuer and the lease itself are targets —
		// issuer revocation kills every lease it signed.
		if off, rev, err := v.revocation.AnyRevoked(
			revocation.P(revocation.ClassIssuer, lease.Issuer),
			revocation.P(revocation.ClassLease, lease.LeaseID)); err != nil {
			result.Add("capability_lease revocation state unavailable")
		} else if rev {
			result.Add(fmt.Sprintf("capability_lease: %s %q is revoked", off.Class, off.Target))
		}
	}

	// Audience binding: a lease minted for another gateway must not
	// authorize actions here. When no expected audience is configured
	// the check is skipped (unsigned-issuer dev mode already fails sig).
	if v.expectedAudience != "" && lease.Audience != v.expectedAudience {
		result.Add("capability_lease.audience does not match this gateway")
	}

	return result
}

// verifyLeaseSignature verifies the lease signature against the trusted
// public key registered for lease.Issuer. The self-asserted
// lease.VerifyKey field is never used for trust decisions.
func (v *Validator) verifyLeaseSignature(lease *models.CapabilityLease) bool {
	if len(lease.Signature) == 0 {
		return false
	}
	verifyKey, ok := v.trustedKeys[lease.Issuer]
	if !ok || len(verifyKey) != ed25519.PublicKeySize {
		return false
	}
	// Canonical length-prefixed payload (see canon.go) — must match
	// ovara_sdk.canon.lease_payload byte-for-byte:
	//   lp(lease_id) lp(issuer) lp(subject) lp(audience)
	//   lparr(allowed_actions) lp(resource_scope)
	//   i64(expiry) i64(issued_at) u32(delegation_depth)
	payload := leasePayload(lease)
	return ed25519.Verify(verifyKey, payload, lease.Signature)
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

// ValidateDelegationChain verifies a delegation chain end-to-end:
//   - every hop is signed by a key in the trusted-issuer registry
//     (caller-minted chains cannot verify — hash is not auth);
//   - hop i+1's issuer equals hop i's subject (chain linkage), so an
//     intermediate delegatee must itself be a trusted issuer to pass
//     authority onward;
//   - the final hop's subject equals the authenticated principal —
//     a chain minted for someone else is useless to the caller;
//   - privilege is non-amplifying: each hop's actions/resource/expiry
//     must be a subset of its parent's;
//   - expiry is honored at every hop; nonce is replay-checked by the
//     caller-supplied seenNonce (evaluator's request nonce cache).
//
// NonceMark is the outcome of consuming a replay identifier:
// NonceMarkFirst = first presentation; NonceMarkSeen = replay;
// NonceMarkFailed = the replay store could not prove state (fail closed).
type NonceMark int

const (
	NonceMarkFirst NonceMark = iota
	NonceMarkSeen
	NonceMarkFailed
)

// NonceMarker consumes a replay identifier. expiresAt is the chain's
// effective expiry — the replay record must outlive the capability or
// the capability could be re-presented after the record ages out.
type NonceMarker func(replayKey string, expiresAt time.Time) NonceMark

func (v *Validator) ValidateDelegationChain(chain *models.DelegationChain, subject string, seenNonce NonceMarker) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if chain == nil {
		return result
	}

	auths := chain.Authorities
	if len(auths) == 0 {
		result.Add("delegation_chain.authorities is required and must not be empty")
		return result
	}
	// Depth bound: long chains expand the attack surface without adding
	// authority — 8 covers any realistic issuer→…→agent path.
	if len(auths) > 8 {
		result.Add("delegation_chain exceeds maximum depth (8)")
		return result
	}

	if chain.ChainHash != "" && !v.verifyChainHash(chain) {
		result.Add("delegation_chain.chain_hash verification failed")
	}

	// Replay identity: the TERMINAL hop's signed nonce, namespaced by its
	// issuer. It is inside the signed payload, so an attacker cannot
	// mutate the replay identifier without invalidating the signature —
	// the signature covers the nonce, the nonce feeds the replay cache.
	// The seenNonce mark is deferred until every cryptographic check has
	// passed (below): marking early would let a forged chain poison a
	// victim's nonce and deny the legitimate presentation.
	terminal := auths[len(auths)-1]
	if strings.TrimSpace(terminal.Nonce) == "" {
		result.Add("delegation_chain terminal hop nonce is required (replay protection)")
	}

	var prevSub, prevSig string
	var prevExpiry time.Time // zero = parent unbounded; unset hops inherit
	prevActions := []string{"*"}
	prevResource := "*"
	var revPairs []revocation.Pair // revocation targets of sig-verified hops

	for i, a := range auths {
		if strings.TrimSpace(a.Issuer) == "" {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].issuer is required", i))
		}
		if strings.TrimSpace(a.SubjectID) == "" {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].subject_id is required", i))
		}
		if i > 0 && a.Issuer != prevSub {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].issuer must equal previous hop's subject_id (chain linkage)", i))
		}
		if a.Issuer == a.SubjectID {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d]: self-delegation is not permitted", i))
		}
		if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(time.Now()) {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d] is expired", i))
		}
		if v.expectedAudience != "" && a.Audience != "" && a.Audience != v.expectedAudience {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].audience does not match this gateway", i))
		}

		// Scope grammar: every asserted scope must be well-formed.
		if a.ResourceScope != "" && !validScope(a.ResourceScope) {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].resource_scope is not a valid scope", i))
		}

		// Non-amplification: child scope ⊆ parent scope (restricted
		// grammar — see scope.go for the provable containment rules).
		if !subsetOfActions(a.Actions, prevActions) {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].actions expands parent authority", i))
		}
		if a.ResourceScope != "" && !scopeContains(prevResource, a.ResourceScope) {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].resource_scope expands parent authority", i))
		}
		if !a.ExpiresAt.IsZero() && !prevExpiry.IsZero() && a.ExpiresAt.After(prevExpiry) {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].expires_at exceeds parent expiry", i))
		}

		// Signature: ed25519 over canonical hop payload linked to the
		// previous signature. Only registry keys verify — a caller
		// cannot mint a hop.
		if len(a.Signature) == 0 {
			result.Add(fmt.Sprintf("delegation_chain.authorities[%d].signature is required", i))
		} else {
			key, ok := v.trustedKeys[a.Issuer]
			if !ok || len(key) != ed25519.PublicKeySize {
				result.Add(fmt.Sprintf("delegation_chain.authorities[%d].issuer %q is not a trusted issuer", i, a.Issuer))
			} else if !ed25519.Verify(key, hopPayload(auths, i, prevSig), a.Signature) {
				result.Add(fmt.Sprintf("delegation_chain.authorities[%d].signature verification failed", i))
			} else {
				// Hop is cryptographically bound — its issuer and its
				// presentation key sha256(lp(issuer)‖lp(nonce)) become
				// revocation targets (P2.3.4). Per-hop granularity is
				// what makes "revoke A→B kills A→B→C" work while a
				// sibling presentation under the same issuer survives.
				revPairs = append(revPairs,
					revocation.P(revocation.ClassIssuer, a.Issuer),
					revocation.P(revocation.ClassDelegation, delegReplayKey(a)))
			}
		}

		prevSub = a.SubjectID
		prevSig = hex.EncodeToString(a.Signature)
		if !a.ExpiresAt.IsZero() {
			prevExpiry = a.ExpiresAt
		}
		if len(a.Actions) > 0 {
			prevActions = a.Actions
		}
		if a.ResourceScope != "" {
			prevResource = a.ResourceScope
		}
	}

	// Final hop's subject is the delegatee — it must be the caller.
	if subject != "" && auths[len(auths)-1].SubjectID != subject {
		result.Add("delegation_chain final subject does not match the authenticated principal")
	}

	// Revocation check on the verified hops — ONE consistent absorbed
	// view so a revocation committed mid-validation is either fully
	// visible or fully not, never torn across hops. Issuer revocation
	// invalidates every descendant of its signed hops (the hop's own
	// pair is checked here, so chains containing it die); presentation
	// revocation kills every chain containing that hop. A storage
	// failure is UNKNOWN → deny, never "not revoked".
	if v.revocation != nil && len(revPairs) > 0 {
		if off, rev, err := v.revocation.AnyRevoked(revPairs...); err != nil {
			result.Add("delegation_chain revocation state unavailable")
		} else if rev {
			result.Add(fmt.Sprintf("delegation_chain: %s %q is revoked", off.Class, off.Target))
		}
	}

	// Replay mark LAST: only a fully-validated chain may consume its
	// nonce. A forged or malformed chain must not poison the cache.
	// The key is a canonical (issuer, nonce) tuple — length-prefix +
	// hash so no field-boundary collision is possible ("a|b","c" vs
	// "a","b|c" under pipe-join). prevExpiry is the chain's effective
	// expiry (children cannot exceed parents; zero = unbounded).
	if result.Valid && seenNonce != nil && strings.TrimSpace(terminal.Nonce) != "" {
		switch seenNonce(delegReplayKey(terminal), prevExpiry) {
		case NonceMarkSeen:
			result.Add("delegation replay: terminal nonce already presented")
		case NonceMarkFailed:
			result.Add("delegation replay state unavailable")
		}
	}

	return result
}

// delegReplayKey derives the unambiguous replay identity of a chain:
// sha256 over the canonical (issuer, nonce) tuple of the terminal hop.
func delegReplayKey(terminal models.Authority) string {
	return hex.EncodeToString(sha256Hash(
		(&lpBuilder{}).str(terminal.Issuer).str(terminal.Nonce).buf))
}

// ChainRevocationIDs returns the revocation identifiers an authority
// record (approval, continuation) must retain so a later claim can be
// revalidated (P2.3.4): EVERY hop's presentation key — the same set
// the validator checks at eval — plus every hop issuer. Recording
// only the terminal key would let a mid-hop presentation revocation
// slip past claim-time enforcement: revoking (A,nAB) kills A→B→C at
// eval, so the continuation derived from it must die at claim too.
func ChainRevocationIDs(chain *models.DelegationChain) (delegationKeys []string, issuers []string) {
	if chain == nil || len(chain.Authorities) == 0 {
		return nil, nil
	}
	issuers = make([]string, 0, len(chain.Authorities))
	delegationKeys = make([]string, 0, len(chain.Authorities))
	for _, a := range chain.Authorities {
		issuers = append(issuers, a.Issuer)
		delegationKeys = append(delegationKeys, delegReplayKey(a))
	}
	return delegationKeys, issuers
}

// hopPayload is the canonical signed payload for authority i (see
// canon.go — must match ovara_sdk.canon.hop_payload byte-for-byte):
//
//	lp(issuer) lp(subject_id) lp(audience) lp(resource_scope)
//	lparr(actions) i64(expires_at) i64(delegated_at)
//	lp(nonce) lp(prev_sig_hex)
//
// All asserted fields plus the previous hop's signature hex are covered
// — reordering, splicing, or mutating any field (including the nonce)
// invalidates the signature.
func hopPayload(auths []models.Authority, i int, prevSig string) []byte {
	a := auths[i]
	return (&lpBuilder{}).
		str(a.Issuer).str(a.SubjectID).str(a.Audience).str(a.ResourceScope).
		strs(a.Actions).
		i64(a.ExpiresAt.Unix()).i64(a.DelegatedAt.Unix()).
		str(a.Nonce).str(prevSig).
		buf
}

// leasePayload is the canonical signed payload for a capability lease.
func leasePayload(lease *models.CapabilityLease) []byte {
	return (&lpBuilder{}).
		str(lease.LeaseID).str(lease.Issuer).str(lease.Subject).str(lease.Audience).
		strs(lease.AllowedActions).str(lease.ResourceScope).
		i64(lease.Expiry.Unix()).i64(lease.IssuedAt.Unix()).
		u32(uint32(lease.DelegationDepth)).
		buf
}

// subsetOfActions: child ⊆ parent. Empty child = inherit parent scope;
// "*" anywhere = wildcard for that level.
func subsetOfActions(child, parent []string) bool {
	for _, p := range parent {
		if p == "*" {
			return true
		}
	}
	if len(child) == 0 {
		return true
	}
	set := map[string]bool{}
	for _, p := range parent {
		set[p] = true
	}
	for _, c := range child {
		if c == "*" || !set[c] {
			return false
		}
	}
	return true
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

// TerminalCapability returns the effective capability a valid chain
// grants the terminal subject: the last hop that explicitly set each
// field wins (hops may only narrow or inherit, so the terminal hop's
// effective scope is the chain's narrowest).
func TerminalCapability(chain *models.DelegationChain) (actions []string, resourceScope string) {
	if chain == nil {
		return nil, ""
	}
	actions = []string{"*"}
	resourceScope = "*"
	for _, a := range chain.Authorities {
		if len(a.Actions) > 0 {
			actions = a.Actions
		}
		if a.ResourceScope != "" {
			resourceScope = a.ResourceScope
		}
	}
	return actions, resourceScope
}

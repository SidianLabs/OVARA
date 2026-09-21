package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type CapabilityLease struct {
	LeaseID          string    `json:"lease_id"`
	Issuer           string    `json:"issuer"`
	Subject          string    `json:"subject"`
	AllowedActions   []string  `json:"allowed_actions"`
	ResourceScope    string    `json:"resource_scope"`
	Expiry           time.Time `json:"expiry"`
	DelegationDepth  int       `json:"delegation_depth"`
	RevocationHandle string    `json:"revocation_handle,omitempty"`
	Revoked          bool      `json:"revoked,omitempty"`
	IssuedAt         time.Time `json:"issued_at"`
	Signature        []byte    `json:"signature,omitempty"`
}

func IssueCapabilityLease(issuer *AgentIdentity, issuerKey ed25519.PrivateKey, subject string, allowedActions []string, resourceScope string, ttlMinutes int, delegationDepth int) (*CapabilityLease, error) {
	if issuer == nil {
		return nil, fmt.Errorf("issuer identity is required")
	}
	if !issuer.IsActive() {
		return nil, fmt.Errorf("issuer identity is not active")
	}
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if len(allowedActions) == 0 {
		return nil, fmt.Errorf("at least one allowed action is required")
	}
	if delegationDepth < 0 {
		return nil, fmt.Errorf("delegation depth cannot be negative")
	}
	if ttlMinutes <= 0 {
		return nil, fmt.Errorf("ttl_minutes must be positive")
	}

	now := time.Now().UTC()
	idBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", issuer.ID, subject, now.UnixNano())))
	leaseID := "lse_" + hex.EncodeToString(idBytes[:8])

	cl := &CapabilityLease{
		LeaseID:         leaseID,
		Issuer:          issuer.ID,
		Subject:         subject,
		AllowedActions:  allowedActions,
		ResourceScope:   resourceScope,
		Expiry:          now.Add(time.Duration(ttlMinutes) * time.Minute),
		DelegationDepth: delegationDepth,
		IssuedAt:        now,
	}

	sig := ed25519.Sign(issuerKey, cl.digestPayload())
	cl.Signature = sig
	return cl, nil
}

// digestPayload returns the canonical byte representation of the fields
// covered by the lease signature. The format MUST byte-match what the
// gateway verifier builds in
// runtime/gateway/internal/identity/validator.go (verifyLeaseSignature)
// and what both SDKs use:
//
//	LeaseID|Issuer|Subject|[AllowedActions]|ResourceScope|ExpiryUnix|DelegationDepth|IssuedAtUnix
//
// where [AllowedActions] is Go's fmt %v rendering of a []string
// ("[a b c]") and the timestamps are Unix seconds.
func (c *CapabilityLease) digestPayload() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%v|%s|%d|%d|%d",
		c.LeaseID, c.Issuer, c.Subject, c.AllowedActions,
		c.ResourceScope, c.Expiry.Unix(), c.DelegationDepth, c.IssuedAt.Unix(),
	))
}

func (c *CapabilityLease) Digest() string {
	h := sha256.Sum256(c.digestPayload())
	return hex.EncodeToString(h[:])
}

func (c *CapabilityLease) IsExpired() bool {
	return c.Revoked || time.Now().UTC().After(c.Expiry)
}

func (c *CapabilityLease) HasAction(action string) bool {
	for _, a := range c.AllowedActions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

func (c *CapabilityLease) ScopeCovers(resource string) bool {
	return c.ResourceScope == "" || c.ResourceScope == "*" || c.ResourceScope == resource
}

func (c *CapabilityLease) Verify(publicKey []byte) bool {
	if len(c.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, c.digestPayload(), c.Signature)
}

func (c *CapabilityLease) CanDelegate() bool {
	return c.DelegationDepth > 0
}

func (c *CapabilityLease) Validate() []string {
	var errs []string
	if c.Issuer == "" {
		errs = append(errs, "issuer is required")
	}
	if c.Subject == "" {
		errs = append(errs, "subject is required")
	}
	if len(c.AllowedActions) == 0 {
		errs = append(errs, "at least one allowed action is required")
	}
	if c.Expiry.IsZero() {
		errs = append(errs, "expiry is required")
	}
	return errs
}

package identity

import (
	"crypto/ed25519"
	"fmt"
)

type Issuer struct {
	registry   *Registry
	leaseStore *LeaseStore
}

func NewIssuer(registry *Registry, leaseStore *LeaseStore) *Issuer {
	return &Issuer{
		registry:   registry,
		leaseStore: leaseStore,
	}
}

func (i *Issuer) CreateIdentity(issuerName, subjectID, owner string) (*AgentIdentity, ed25519.PrivateKey, error) {
	id, priv, err := NewAgentIdentity(issuerName, subjectID, owner)
	if err != nil {
		return nil, nil, fmt.Errorf("create identity: %w", err)
	}
	if err := i.registry.Register(id); err != nil {
		return nil, nil, fmt.Errorf("register identity: %w", err)
	}
	return id, priv, nil
}

func (i *Issuer) IssueLease(issuerID string, issuerKey ed25519.PrivateKey, subject string, allowedActions []string, resourceScope string, ttlMinutes int, delegationDepth int) (*CapabilityLease, error) {
	issuer, ok := i.registry.Get(issuerID)
	if !ok {
		return nil, fmt.Errorf("issuer identity not found: %s", issuerID)
	}
	if !issuer.IsActive() {
		return nil, fmt.Errorf("issuer identity is not active: %s", issuerID)
	}

	lease, err := IssueCapabilityLease(issuer, issuerKey, subject, allowedActions, resourceScope, ttlMinutes, delegationDepth)
	if err != nil {
		return nil, fmt.Errorf("issue lease: %w", err)
	}

	if err := i.leaseStore.Store(lease); err != nil {
		return nil, fmt.Errorf("store lease: %w", err)
	}
	return lease, nil
}

func (i *Issuer) RevokeLease(leaseID string) error {
	lease, ok := i.leaseStore.Get(leaseID)
	if !ok {
		return fmt.Errorf("lease not found: %s", leaseID)
	}
	lease.Expiry = lease.IssuedAt
	return nil
}

func (i *Issuer) ActiveLeasesFor(subject string) []*CapabilityLease {
	var active []*CapabilityLease
	for _, l := range i.leaseStore.ListBySubject(subject) {
		if !l.IsExpired() {
			active = append(active, l)
		}
	}
	return active
}

package identity

import (
	"bytes"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// Canonical-preimage mutation property for delegation signing
// (canon.go / lpBuilder): mutate ONE covered field — to a different
// value of the SAME length where strings are involved — and the
// signed bytes must differ. This is the property a content-dropping
// framer violates; the vectors these payloads feed (delegation hops,
// capability leases) are the root of every authority check.
func TestHopPayload_FieldMutationChangesPreimage(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	mk := func() []models.Authority {
		return []models.Authority{{
			Issuer: "iss_a", SubjectID: "sub_a", Audience: "domA",
			ResourceScope: "shell:*", Actions: []string{"shell", "fetch"},
			ExpiresAt: at.Add(time.Hour), DelegatedAt: at, Nonce: "nonce_a",
		}}
	}
	base := hopPayload(mk(), 0, "prev_sig_a")
	mutations := []struct {
		name string
		mut  func([]models.Authority)
	}{
		{"issuer", func(a []models.Authority) { a[0].Issuer = "iss_b" }},
		{"subject", func(a []models.Authority) { a[0].SubjectID = "sub_b" }},
		{"audience", func(a []models.Authority) { a[0].Audience = "domB" }},
		{"resource_scope", func(a []models.Authority) { a[0].ResourceScope = "shell:+" }},
		{"action_elem", func(a []models.Authority) { a[0].Actions[0] = "shelL" }},
		{"action_count", func(a []models.Authority) { a[0].Actions = append(a[0].Actions, "exec") }},
		{"expires_at", func(a []models.Authority) { a[0].ExpiresAt = a[0].ExpiresAt.Add(time.Second) }},
		{"delegated_at", func(a []models.Authority) { a[0].DelegatedAt = a[0].DelegatedAt.Add(time.Second) }},
		{"nonce", func(a []models.Authority) { a[0].Nonce = "nonce_b" }},
	}
	for _, m := range mutations {
		a := mk()
		m.mut(a)
		if bytes.Equal(hopPayload(a, 0, "prev_sig_a"), base) {
			t.Errorf("%s: hop mutation produced identical payload", m.name)
		}
	}
	// Chain linkage — the previous hop's signature is inside the bytes.
	if bytes.Equal(hopPayload(mk(), 0, "prev_sig_b"), base) {
		t.Error("prev_sig mutation produced identical payload")
	}
}

func TestLeasePayload_FieldMutationChangesPreimage(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	mk := func() *models.CapabilityLease {
		return &models.CapabilityLease{
			LeaseID: "lease_a", Issuer: "iss_a", Subject: "sub_a",
			Audience: "domA", AllowedActions: []string{"shell", "fetch"},
			ResourceScope: "shell:*", Expiry: at.Add(time.Hour),
			IssuedAt: at, DelegationDepth: 2,
		}
	}
	base := leasePayload(mk())
	mutations := []struct {
		name string
		mut  func(*models.CapabilityLease)
	}{
		{"lease_id", func(l *models.CapabilityLease) { l.LeaseID = "lease_b" }},
		{"issuer", func(l *models.CapabilityLease) { l.Issuer = "iss_b" }},
		{"subject", func(l *models.CapabilityLease) { l.Subject = "sub_b" }},
		{"audience", func(l *models.CapabilityLease) { l.Audience = "domB" }},
		{"action_elem", func(l *models.CapabilityLease) { l.AllowedActions[0] = "shelL" }},
		{"action_count", func(l *models.CapabilityLease) { l.AllowedActions = l.AllowedActions[:1] }},
		{"resource_scope", func(l *models.CapabilityLease) { l.ResourceScope = "shell:+" }},
		{"expiry", func(l *models.CapabilityLease) { l.Expiry = l.Expiry.Add(time.Second) }},
		{"issued_at", func(l *models.CapabilityLease) { l.IssuedAt = l.IssuedAt.Add(time.Second) }},
		{"delegation_depth", func(l *models.CapabilityLease) { l.DelegationDepth = 3 }},
	}
	for _, m := range mutations {
		l := mk()
		m.mut(l)
		if bytes.Equal(leasePayload(l), base) {
			t.Errorf("%s: lease mutation produced identical payload", m.name)
		}
	}
}

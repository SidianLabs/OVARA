// P2.3.4 security gate — adversarial validator tests beyond the
// implementation suite: 4-deep chains, every-position issuer kills,
// delegation×lease interaction matrix, sibling granularity under a
// real (file-backed) registry rather than the fake checker.
package identity

import (
	"crypto/ed25519"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
)

func gateValidator(t *testing.T, issuers ...string) (*Validator, *gwidentity.Registry, map[string]ed25519.PrivateKey) {
	t.Helper()
	trusted := map[string][]byte{}
	privs := map[string]ed25519.PrivateKey{}
	for _, iss := range issuers {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		trusted[iss] = pub
		privs[iss] = priv
	}
	reg, err := gwidentity.Open(t.TempDir() + "/reg.jsonl")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	t.Cleanup(func() { reg.Close() })
	v := NewValidatorWithTrustedKeys(trusted)
	v.SetRevocation(reg)
	return v, reg, privs
}

// §6 — A→B→C→D: revoking ANY issuer position kills the whole chain.
func TestGate_FourHopIssuerKills(t *testing.T) {
	for _, kill := range []string{"A", "B", "C"} {
		v, reg, privs := gateValidator(t, "A", "B", "C")
		chain := testChain(t, privs,
			models.Authority{Issuer: "A", SubjectID: "B", Nonce: "nAB"},
			models.Authority{Issuer: "B", SubjectID: "C", Nonce: "nBC"},
			models.Authority{Issuer: "C", SubjectID: "agent-D", Nonce: "nCD"})
		if r := v.ValidateDelegationChain(chain, "agent-D", nil); !r.Valid {
			t.Fatalf("baseline must validate: %v", r.Reasons)
		}
		if _, err := reg.Revoke("issuer", kill, "gate", "kill "+kill); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if r := v.ValidateDelegationChain(chain, "agent-D", nil); r.Valid {
			t.Fatalf("issuer %s revoked — chain must deny", kill)
		}
	}
}

// §6 — a revoked mid-chain PRESENTATION kills descendants; siblings of
// that presentation survive. Uses the REAL journal end to end.
func TestGate_MidHopPresentationKillsDescendants(t *testing.T) {
	v, reg, privs := gateValidator(t, "A", "B")
	chain := testChain(t, privs,
		models.Authority{Issuer: "A", SubjectID: "B", Nonce: "nAB"},
		models.Authority{Issuer: "B", SubjectID: "agent", Nonce: "nB"})
	sibling := testChain(t, privs,
		models.Authority{Issuer: "A", SubjectID: "B", Nonce: "nAB2"},
		models.Authority{Issuer: "B", SubjectID: "agent", Nonce: "nB2"})

	// Revoke the A→B presentation — the FIRST hop's key.
	if _, err := reg.Revoke("delegation", delegReplayKey(chain.Authorities[0]), "gate", "kill A→B"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r := v.ValidateDelegationChain(chain, "agent", nil); r.Valid {
		t.Fatal("chain containing revoked hop presentation must deny")
	}
	if r := v.ValidateDelegationChain(sibling, "agent", nil); !r.Valid {
		t.Fatalf("sibling chain must survive: %v", r.Reasons)
	}
}

// §21 — delegation × lease interaction: no valid component compensates
// for a revoked one.
func TestGate_DelegationLeaseMatrix(t *testing.T) {
	cases := []struct {
		name       string
		revokeDleg bool
		revokeIss  bool
		revokeLse  bool
	}{
		{"all active", false, false, false},
		{"delegation revoked", true, false, false},
		{"lease revoked", false, false, true},
		{"issuer revoked", false, true, false},
		{"delegation+lease revoked", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, reg, privs := gateValidator(t, "iss", "lease-iss")
			chain := testChain(t, privs,
				models.Authority{Issuer: "iss", SubjectID: "agent", Nonce: "n1"})
			lease := &models.CapabilityLease{
				LeaseID: "lse-m", Issuer: "lease-iss", Subject: "agent",
				AllowedActions: []string{"shell"}, ResourceScope: "*",
				Expiry: time.Now().Add(time.Hour),
			}
			signTestLease(t, lease, privs["lease-iss"])
			if tc.revokeDleg {
				reg.Revoke("delegation", delegReplayKey(chain.Authorities[0]), "g", "")
			}
			if tc.revokeIss {
				reg.Revoke("issuer", "iss", "g", "")
			}
			if tc.revokeLse {
				reg.Revoke("lease", "lse-m", "g", "")
			}
			// Chain validity tracks delegation + issuer revocation only;
			// lease validity tracks lease + ITS issuer (lease-iss, never
			// revoked here). Revoked components never compensate.
			wantChain := !tc.revokeDleg && !tc.revokeIss
			wantLease := !tc.revokeLse
			if r := v.ValidateDelegationChain(chain, "agent", nil); r.Valid != wantChain {
				t.Fatalf("chain valid=%v want %v", r.Valid, wantChain)
			}
			if r := v.ValidateCapabilityLease(lease); r.Valid != wantLease {
				t.Fatalf("lease valid=%v want %v", r.Valid, wantLease)
			}
		})
	}
}

// §20 — issuer revocation does not leak across issuers: lease from
// issuer B stays valid when issuer A dies.
func TestGate_IssuerRevocationDoesNotLeak(t *testing.T) {
	v, reg, privs := gateValidator(t, "iss-A", "iss-B")
	leaseB := &models.CapabilityLease{
		LeaseID: "lse-B", Issuer: "iss-B", Subject: "agent",
		AllowedActions: []string{"shell"}, ResourceScope: "*",
		Expiry: time.Now().Add(time.Hour),
	}
	signTestLease(t, leaseB, privs["iss-B"])
	if _, err := reg.Revoke("issuer", "iss-A", "gate", "kill A"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r := v.ValidateCapabilityLease(leaseB); !r.Valid {
		t.Fatalf("unrelated issuer's lease must survive: %v", r.Reasons)
	}
}

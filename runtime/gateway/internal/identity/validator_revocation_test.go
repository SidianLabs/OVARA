package identity

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/revocation"
)

// fakeChecker is a controllable revocation view for validator tests —
// the gwidentity-backed integration is covered in revoke_test.go.
type fakeChecker struct {
	revoked map[revocation.Pair]bool
	err     error // injected storage failure → UNKNOWN
	epoch   uint64
}

func (f *fakeChecker) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	if f.err != nil {
		return revocation.Pair{}, false, f.err
	}
	for _, p := range pairs {
		if f.revoked[p] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

func (f *fakeChecker) Epoch() (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.epoch, nil
}

func (f *fakeChecker) revoke(class revocation.Class, target string) {
	f.revoked[revocation.P(class, target)] = true
}

func newRevValidator(t *testing.T, issuers ...string) (*Validator, *fakeChecker, map[string]ed25519.PrivateKey) {
	t.Helper()
	trusted := map[string][]byte{}
	privs := map[string]ed25519.PrivateKey{}
	for _, iss := range issuers {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("keygen %s: %v", iss, err)
		}
		trusted[iss] = pub
		privs[iss] = priv
	}
	fc := &fakeChecker{revoked: map[revocation.Pair]bool{}}
	v := NewValidatorWithTrustedKeys(trusted)
	v.SetRevocation(fc)
	return v, fc, privs
}

func testChain(t *testing.T, privs map[string]ed25519.PrivateKey, hops ...models.Authority) *models.DelegationChain {
	t.Helper()
	chain := &models.DelegationChain{Authorities: hops, Depth: len(hops)}
	signHops(chain, privs)
	return chain
}

// RVI-01: a revoked issuer cannot authorize new execution.
func TestRevocation_IssuerRevokedDenies(t *testing.T) {
	v, fc, privs := newRevValidator(t, "root")
	chain := testChain(t, privs,
		models.Authority{Issuer: "root", SubjectID: "agent-1", Nonce: "n1"})
	if r := v.ValidateDelegationChain(chain, "agent-1", nil); !r.Valid {
		t.Fatalf("baseline must validate: %v", r.Reasons)
	}
	fc.revoke(revocation.ClassIssuer, "root")
	if r := v.ValidateDelegationChain(chain, "agent-1", nil); r.Valid {
		t.Fatal("revoked issuer must deny")
	}
}

// RVI-02: revoking an issuer invalidates descendants of its hops.
// A→B→C: revoking A or B kills the whole chain.
func TestRevocation_MidChainIssuerKillsDescendants(t *testing.T) {
	v, fc, privs := newRevValidator(t, "root", "mid")
	chain := testChain(t, privs,
		models.Authority{Issuer: "root", SubjectID: "mid", Nonce: "n1"},
		models.Authority{Issuer: "mid", SubjectID: "agent-1", Nonce: "n2"})
	if r := v.ValidateDelegationChain(chain, "agent-1", nil); !r.Valid {
		t.Fatalf("baseline must validate: %v", r.Reasons)
	}
	fc.revoke(revocation.ClassIssuer, "mid")
	if r := v.ValidateDelegationChain(chain, "agent-1", nil); r.Valid {
		t.Fatal("revoked mid-chain issuer must deny the whole chain")
	}
}

// RVI-03: revoking one presentation does not revoke siblings.
// Same issuer, two nonces: killing A's presentation leaves B valid.
func TestRevocation_SiblingPresentationSurvives(t *testing.T) {
	v, fc, privs := newRevValidator(t, "root")
	chainA := testChain(t, privs, models.Authority{Issuer: "root", SubjectID: "agent-1", Nonce: "nonce-A"})
	chainB := testChain(t, privs, models.Authority{Issuer: "root", SubjectID: "agent-1", Nonce: "nonce-B"})

	// Revoke A's presentation key — sha256(lp(root)‖lp(nonce-A)).
	fc.revoke(revocation.ClassDelegation, delegReplayKey(chainA.Authorities[0]))

	if r := v.ValidateDelegationChain(chainA, "agent-1", nil); r.Valid {
		t.Fatal("revoked presentation must deny")
	}
	if r := v.ValidateDelegationChain(chainB, "agent-1", nil); !r.Valid {
		t.Fatalf("sibling presentation must survive: %v", r.Reasons)
	}
}

// RVI-09: storage failure is UNKNOWN → deny, never allow.
func TestRevocation_StorageFailureDenies(t *testing.T) {
	v, fc, privs := newRevValidator(t, "root")
	chain := testChain(t, privs, models.Authority{Issuer: "root", SubjectID: "agent-1", Nonce: "n1"})
	fc.err = fmt.Errorf("simulated journal corruption")
	if r := v.ValidateDelegationChain(chain, "agent-1", nil); r.Valid {
		t.Fatal("revocation storage failure must deny")
	}
}

// RVI-04: a revoked lease cannot authorize — lease class check inside
// ValidateCapabilityLease.
func TestRevocation_LeaseRevokedDenies(t *testing.T) {
	v, fc, privs := newRevValidator(t, "ovara")
	lease := &models.CapabilityLease{
		LeaseID:        "lse-1",
		Issuer:         "ovara",
		Subject:        "agent-1",
		AllowedActions: []string{"shell"},
		ResourceScope:  "*",
		Expiry:         time.Now().Add(time.Hour),
	}
	signTestLease(t, lease, privs["ovara"])
	if r := v.ValidateCapabilityLease(lease); !r.Valid {
		t.Fatalf("baseline must validate: %v", r.Reasons)
	}
	fc.revoke(revocation.ClassLease, "lse-1")
	if r := v.ValidateCapabilityLease(lease); r.Valid {
		t.Fatal("revoked lease must deny")
	}
}

// RVI-04 (issuer side): a lease from a revoked issuer cannot authorize.
func TestRevocation_LeaseFromRevokedIssuerDenies(t *testing.T) {
	v, fc, privs := newRevValidator(t, "ovara")
	lease := &models.CapabilityLease{
		LeaseID:        "lse-2",
		Issuer:         "ovara",
		Subject:        "agent-1",
		AllowedActions: []string{"shell"},
		ResourceScope:  "*",
		Expiry:         time.Now().Add(time.Hour),
	}
	signTestLease(t, lease, privs["ovara"])
	fc.revoke(revocation.ClassIssuer, "ovara")
	if r := v.ValidateCapabilityLease(lease); r.Valid {
		t.Fatal("lease from revoked issuer must deny")
	}
}

// RVI-13: replay and revocation are independent. A revoked-never-
// consumed presentation stays denied; a valid first presentation marks
// consumed; re-presenting it denies on replay even when NOT revoked.
func TestRevocation_ReplayIndependent(t *testing.T) {
	v, fc, privs := newRevValidator(t, "root")
	chain := testChain(t, privs, models.Authority{Issuer: "root", SubjectID: "agent-1", Nonce: "n1"})

	seen := map[string]bool{}
	mark := func(key string, exp time.Time) NonceMark {
		if seen[key] {
			return NonceMarkSeen
		}
		seen[key] = true
		return NonceMarkFirst
	}

	// Revoked BEFORE first presentation: denies on revocation, and the
	// nonce is NOT consumed (mark never runs — revocation precedes it).
	fc.revoke(revocation.ClassDelegation, delegReplayKey(chain.Authorities[0]))
	if r := v.ValidateDelegationChain(chain, "agent-1", mark); r.Valid {
		t.Fatal("revoked presentation must deny")
	}
	if len(seen) != 0 {
		t.Fatal("revoked chain must not consume the replay nonce")
	}

	// Un-revoke is impossible by design; simulate a fresh valid chain.
	fc = &fakeChecker{revoked: map[revocation.Pair]bool{}}
	v.SetRevocation(fc)
	if r := v.ValidateDelegationChain(chain, "agent-1", mark); !r.Valid {
		t.Fatalf("fresh chain must validate: %v", r.Reasons)
	}
	// Re-presentation: denied on replay, independent of revocation.
	if r := v.ValidateDelegationChain(chain, "agent-1", mark); r.Valid {
		t.Fatal("replayed presentation must deny")
	}
}

// ChainRevocationIDs — the identifiers recorded for claim-time checks.
// EVERY hop's presentation key must be captured: eval checks each hop's
// key, so claim-time must see the same set or a mid-hop kill slips.
func TestChainRevocationIDs(t *testing.T) {
	_, _, privs := newRevValidator(t, "root", "mid")
	chain := testChain(t, privs,
		models.Authority{Issuer: "root", SubjectID: "mid", Nonce: "n1"},
		models.Authority{Issuer: "mid", SubjectID: "agent-1", Nonce: "n2"})
	keys, issuers := ChainRevocationIDs(chain)
	if len(keys) != 2 ||
		keys[0] != delegReplayKey(chain.Authorities[0]) ||
		keys[1] != delegReplayKey(chain.Authorities[1]) {
		t.Fatalf("must capture every hop key, got %v", keys)
	}
	if len(issuers) != 2 || issuers[0] != "root" || issuers[1] != "mid" {
		t.Fatalf("issuers: %v", issuers)
	}
	if k, _ := ChainRevocationIDs(nil); k != nil {
		t.Fatal("nil chain → empty ids")
	}
}

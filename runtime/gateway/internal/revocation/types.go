// Package revocation defines the shared revocation-checking contract
// used by every execution-capable path (P2.3.4).
//
// Revocation is a security boundary, not metadata: a previously valid
// authorization must not remain executable merely because it was
// issued before revocation. The Checker interface is deliberately
// error-bearing — a storage failure yields an UNKNOWN state that must
// never be read as "not revoked" (fail closed, never ERROR→allow).
//
// Revocation classes are distinct authority categories and MUST NOT
// be collapsed into one generic flag:
//
//	ClassIssuer      — kills every delegation hop and lease signed by
//	                   that issuer (incl. descendant presentations)
//	ClassDelegation  — kills one capability presentation identified
//	                   by its canonical presentation key
//	                   sha256(lp(issuer)‖lp(nonce)) and every chain
//	                   containing that hop
//	ClassLease       — kills one lease's execution authority
//
// Credential revocation and identity suspension/retirement are
// enforced by the P2.2 identity registry and stay separate.
package revocation

// Class identifies a revocation category.
type Class string

const (
	ClassIssuer     Class = "issuer"
	ClassDelegation Class = "delegation"
	ClassLease      Class = "lease"
)

// Pair is one (class, canonical-target) revocation query.
type Pair struct {
	Class  Class  `json:"class"`
	Target string `json:"target"`
}

// P is a small constructor for readable call sites.
func P(class Class, target string) Pair { return Pair{Class: class, Target: target} }

// PairsFor builds the query set for a recorded authority triple —
// the presented lease, EVERY hop presentation key of the delegation
// chain (the same set eval checks — a mid-hop kill must reach
// claim-time too), and every hop issuer. Shared by the continuation
// claim path and the approval resume path so both consult identical
// targets.
func PairsFor(leaseID string, delegationKeys, issuers []string) []Pair {
	var pairs []Pair
	if leaseID != "" {
		pairs = append(pairs, P(ClassLease, leaseID))
	}
	for _, k := range delegationKeys {
		if k != "" {
			pairs = append(pairs, P(ClassDelegation, k))
		}
	}
	for _, iss := range issuers {
		pairs = append(pairs, P(ClassIssuer, iss))
	}
	return pairs
}

// Checker is the shared revocation boundary. Implementations absorb
// the durable revocation view under their lock before answering so a
// query reflects the latest committed state (cross-process included).
type Checker interface {
	// AnyRevoked reports whether any pair is revoked under one
	// consistent view. It returns the first offending pair found.
	// A non-nil error means the revocation state is UNKNOWN
	// (storage failure, corruption, rollback) — callers must treat
	// it as unable-to-authorize, never as "not revoked".
	AnyRevoked(pairs ...Pair) (offender Pair, revoked bool, err error)

	// Epoch is the domain revocation counter. It is durable,
	// monotonic, and shared across gateways on the same store.
	// A non-nil error means the epoch is unknown — callers must not
	// satisfy min_epoch requirements from an unknown epoch.
	Epoch() (uint64, error)
}

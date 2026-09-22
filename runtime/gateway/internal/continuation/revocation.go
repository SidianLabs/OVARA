// Claim-time revocation enforcement for continuations (P2.3.4).
//
// A continuation is a queued authorization — created under the
// revocation state at creation time but EXECUTED later. The shared
// boundary: authority is revalidated at the atomic claim/consume
// boundary, and a revocation committed before that check wins —
// the continuation transitions to denied, no execution record is
// created, no external side effect occurs. A revocation committed
// AFTER the check is not retroactive to a legitimately-started
// execution (the gateway does not claim to kill running external
// processes — RVI-14).
package continuation

import (
	"fmt"
	"time"

	"ovara.runtime.gateway/internal/revocation"
)

// RevocationPairs returns every (class, target) the recorded authority
// must be checked against at claim time: the presented lease, the
// chain's terminal presentation key, and each hop issuer.
func (c *Continuation) RevocationPairs() []revocation.Pair {
	return revocation.PairsFor(c.LeaseID, c.DelegationKeys, c.Issuers)
}

// CheckClaimAuthority revalidates a claimed continuation's recorded
// authority against the CURRENT revocation view — one atomic absorb,
// so a revocation committed mid-check is never torn across pairs.
//
//	deny=true            → terminal: transition to denied, audit why
//	err≠nil              → UNKNOWN (storage failure): never execute —
//	                      requeue/skip so the claim fails closed but a
//	                      transient store error doesn't permanently
//	                      kill otherwise-valid work
//	deny=false, err=nil  → authority clear under the current view
func CheckClaimAuthority(rc revocation.Checker, c *Continuation) (deny bool, reason string, err error) {
	// C4 — the continuation's captured authority must still be valid
	// at claim: a lease or delegation hop valid at evaluation must not
	// execute after its expiry. Checked unconditionally (before the
	// revocation boundary) and independent of revocation plumbing.
	if c.AuthorityExpiresAt != nil && !c.AuthorityExpiresAt.After(time.Now()) {
		return true, "captured authority expired before claim", nil
	}
	if rc == nil {
		return false, "", nil // no revocation boundary configured — runtime-only mode
	}
	pairs := c.RevocationPairs()
	if len(pairs) == 0 {
		return false, "", nil // nothing capability-bound recorded — nothing to check
	}
	off, rev, err := rc.AnyRevoked(pairs...)
	if err != nil {
		return false, "", fmt.Errorf("revocation state unavailable: %w", err)
	}
	if rev {
		return true, fmt.Sprintf("%s %q is revoked", off.Class, off.Target), nil
	}
	return false, "", nil
}

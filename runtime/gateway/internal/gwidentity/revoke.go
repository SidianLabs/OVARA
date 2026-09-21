// Revocation authority (P2.3.4). Revocation records live in the same
// domain journal as gateway keys and enrollment grants — deliberately
// not a separate store:
//
//   - one file = one trust domain = one flock = one serialization
//     point, so every gateway in the domain observes the same
//     revocation state (shared-file cross-gateway consistency)
//   - the running hash chain makes revoked entries tamper-evident and
//     a shrunk file fails closed (absorb refuses history rewrite)
//   - the P2.3.3 oracle anchors every mutation, so a restored
//     pre-revocation journal is detected as rollback at reconcile
//   - journal seq IS the domain revocation epoch: durable, monotonic,
//     regression impossible (every mutation — key, grant, revoke —
//     advances it)
//
// Authority = write access to the domain journal (flock-serialized,
// same boundary as enrollment grants) — via gwctl or an operator-only
// API path. An agent credential cannot reach either; the revocation
// record embeds the operator actor for audit.
//
// Read side: AnyRevoked/Epoch absorb the journal tail under flock
// before answering, so a query sees the latest committed state
// including records written by other processes. A storage failure
// surfaces as err — UNKNOWN, never "not revoked".
package gwidentity

import (
	"fmt"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/revocation"
)

// ErrBadRevocationClass rejects targets outside the three authority
// categories — revocation classes must not collapse into one flag,
// and a mistyped class must not silently mint a meaningless record.
var ErrBadRevocationClass = fmt.Errorf("gwidentity: revocation class must be %q, %q, or %q",
	revocation.ClassIssuer, revocation.ClassDelegation, revocation.ClassLease)

func validRevocationClass(c string) bool {
	switch revocation.Class(c) {
	case revocation.ClassIssuer, revocation.ClassDelegation, revocation.ClassLease:
		return true
	}
	return false
}

// indexRevoke folds a revoke record into the in-memory index. A
// revocation never un-revokes: later records for the same (class,
// target) are audit duplicates — the kill stands.
func (r *Registry) indexRevoke(rv *RevokeRecord) {
	m := r.revoked[rv.Class]
	if m == nil {
		m = map[string]bool{}
		r.revoked[rv.Class] = m
	}
	if !m[rv.Target] {
		cp := *rv
		r.revokedList = append(r.revokedList, &cp)
	}
	m[rv.Target] = true
}

// Revoke durably revokes one (class, target) under the mutation
// serialization (flock → absorb → append → fsync → index → anchor
// push). actor is the authenticated operator identity — recorded, not
// trusted: the authority is the journal write itself. Revoking an
// already-revoked target is an idempotent no-op that still returns
// the recorded epoch — repeated kills must not append noise records.
//
// Anchor-push failure semantics are inherited from mutate: the local
// revocation IS durable (fail-closed is satisfied — the kill stands),
// the tail is unanchored, and the caller sees the error. Refusing to
// revoke on anchor failure would be fail-open in the wrong direction.
func (r *Registry) Revoke(class, target, actor, reason string) (*RevokeRecord, error) {
	if !validRevocationClass(class) {
		return nil, ErrBadRevocationClass
	}
	if target == "" {
		return nil, fmt.Errorf("gwidentity: revocation target is required")
	}
	if actor == "" {
		actor = "operator"
	}
	rv := &RevokeRecord{Kind: "revoke", Class: class, Target: target,
		Actor: actor, Reason: reason, RevokedAt: time.Now().UTC()}
	dup := false
	var dupSeq uint64
	err := r.mutate(func() ([]any, error) {
		if r.revoked[class][target] {
			dup = true // already revoked — durable record exists; don't re-append
			dupSeq = r.seq // read under mutate's lock — outside it races
			return nil, nil
		}
		return []any{rv}, nil
	})
	if err != nil {
		return nil, err
	}
	if dup {
		// Report the existing epoch without fabricating a new record.
		return &RevokeRecord{Kind: "revoke", Class: class, Target: target,
			Actor: actor, Reason: reason, Seq: dupSeq}, nil
	}
	return rv, nil
}

// absorbLocked refreshes the index under flock for file-backed
// registries — the read-side serialization that makes revocation
// written by another process (gwctl, a peer gateway) visible here.
// In-memory registries have no tail to absorb.
func (r *Registry) absorbLocked() error {
	if r.f == nil {
		return nil
	}
	if err := syscall.Flock(int(r.f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("gateway registry: lock: %w", err)
	}
	defer syscall.Flock(int(r.f.Fd()), syscall.LOCK_UN)
	return r.absorb()
}

// AnyRevoked answers the claim-time revocation question under one
// consistent absorbed view — a revocation committed mid-check is
// either fully visible or fully not, never torn across pairs.
// err ≠ nil ⇒ UNKNOWN ⇒ caller must not authorize.
func (r *Registry) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.absorbLocked(); err != nil {
		return revocation.Pair{}, false, err
	}
	for _, p := range pairs {
		if r.revoked[string(p.Class)][p.Target] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

// Epoch is the domain revocation epoch — the journal sequence, shared
// with every gateway on this store. It advances on every authority
// mutation, never regresses (append-only + shrink refusal), and is
// anchored by the P2.3.3 oracle when configured. In-memory registries
// report the committed in-memory count.
func (r *Registry) Epoch() (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.absorbLocked(); err != nil {
		return 0, err
	}
	return r.seq, nil
}

// Revocations lists the revocation records currently folded — audit
// surface for gwctl, ordered by journal position.
func (r *Registry) Revocations() ([]*RevokeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.absorbLocked(); err != nil {
		return nil, err
	}
	// revokedList preserves journal order — the index is a set, the
	// list is the audit trail.
	out := make([]*RevokeRecord, len(r.revokedList))
	copy(out, r.revokedList)
	return out, nil
}

# Phase 54 Capability Revocation — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-54-capability-revocation`
**Parent**: `phase-53-policy-recovery` (commit `60cac32`)
**Objective**: Make delegated authority more operationally real with lease tracking, revocation, and runtime enforcement

---

## 1. Repository Verification

- **Current branch**: `phase-54-capability-revocation`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Latest commits reviewed** (from parent branch):
  - `60cac32` feat(policy): add local policy history, rollback, and restore workflow
  - `b9ae2f5` feat(evaluator): add Simulate, SimulateBatch, ComparePolicies methods
  - `cf783bb` feat(policy): implement policy simulation, validation, diff, and staged workflow

---

## 2. Current Capability/Lease System Audit

### What's Implemented (Before)
- `models.CapabilityLease` — had LeaseID, Issuer, Subject, AllowedActions, ResourceScope, Expiry, DelegationDepth, RevocationHandle (unused)
- `identity.Validator.ValidateCapabilityLease` — validated expiry and scope
- `Evaluator` checked lease validity but had no revocation tracking

### What's Implemented (Phase 54)
- `capabilities.Store` — tracks active and revoked leases with timestamps
- `GET /v1/capabilities` — lists all tracked leases with counts
- `GET /v1/capabilities/?id=` — get specific lease details
- `POST /v1/capabilities/track` — track a new lease
- `POST /v1/capabilities/revoke` — revoke a lease with reason
- `Evaluator` now checks revocation before policy evaluation
- `EventTypeCapabilityTracked` and `EventTypeCapabilityRevoked` events
- `ReasonCapabilityRevoked` reason code

---

## 3. Implementation Summary

### Milestone B: Capability Lease Store and Inspection

Created `internal/capabilities/store.go`:
- `TrackedLease` — wraps CapabilityLease with CreatedAt, RevokedAt, RevocationReason, GatewayID
- `Store` interface with in-memory implementation
- Methods: Track, Get, List, ListActive, ListRevoked, Revoke, IsRevoked, Clear

Created `internal/handlers/capabilities.go`:
- `GET /v1/capabilities` — lists all with active/revoked counts
- `GET /v1/capabilities/?id=` — get specific lease
- `POST /v1/capabilities/track` — track new lease
- `POST /v1/capabilities/revoke` — revoke lease with reason

### Milestone C: Revocation and Runtime Enforcement

Modified `internal/evaluator/evaluator.go`:
- Added `RevocationChecker` interface
- Added `SetRevocationChecker` method
- Added revocation check BEFORE lease validation in Evaluate flow
- Denies with `ReasonCapabilityRevoked` if lease is in revocation store

Added `ReasonCapabilityRevoked` to `internal/models/decision_response.go`.

### Milestone D: Cross-Object Correlation

- Capability tracking emits events with lease_id, subject, issuer, expiry
- Revocation emits events with lease_id, reason, subject, issuer
- Tracked leases store gateway_id for correlation

### Events Added
- `capability.tracked` — when a lease is tracked
- `capability.revoked` — when a lease is revoked

---

## 4. Live Verification Results

All endpoints verified with curl:

```
=== Track capability ===
POST /v1/capabilities/track → {status: "tracked", lease_id: "cap_test_001"}

=== List capabilities ===
GET /v1/capabilities → count: 1, active_count: 1, revoked_count: 0

=== Revoke capability ===
POST /v1/capabilities/revoke → status: "revoked", revoked_at: ..., revoked_reason: "security incident"

=== Runtime test with valid lease ===
git.pull with valid lease → decision: "allow"

=== Runtime test with revoked lease ===
git.pull with revoked lease → decision: "deny"
```

---

## 5. Files Created/Modified

### Created
- `runtime/gateway/internal/capabilities/store.go` — capability lease store
- `runtime/gateway/internal/capabilities/store_test.go` — 12 store tests
- `runtime/gateway/internal/handlers/capabilities.go` — capability endpoints

### Modified
- `runtime/gateway/cmd/server/main.go` — wired capabilities handler and revocation checker
- `runtime/gateway/internal/events/store.go` — added capability.tracked, capability.revoked events
- `runtime/gateway/internal/models/decision_response.go` — added ReasonCapabilityRevoked
- `runtime/gateway/internal/evaluator/evaluator.go` — added revocation checker interface and enforcement
- `docs/developer/runtime_examples.md` — added capability lease management documentation
- `docs/build/phase_54_capability_revocation_checkpoint.md` — this checkpoint

---

## 6. Tests

### Capability Store Tests (12 tests)
- Track, Get, Get not found
- List, ListActive, ListRevoked
- Revoke, Revoke not found, Revoke already revoked
- IsRevoked, IsRevoked not found, Clear

### All Tests Passing
```
ok  ovara.runtime.gateway/internal/capabilities  0.162s
ok  ovara.runtime.gateway/internal/evaluator     1.004s
ok  ovara.runtime.gateway/internal/handlers      2.012s
```

---

## 7. What's Intentionally Not Implemented

- **Persistent lease store**: Leases are in-memory only. Lost on restart.
- **Lease cleanup**: No automatic pruning of expired leases.
- **Distributed lease state**: Each gateway maintains its own lease state.
- **External revocation integration**: No integration with external revocation lists.
- **Lease issuance**: Leases are tracked but not issued by the gateway.

---

## 8. Merge Recommendation

**Ready to merge.**

The phase is complete with:
- Capability lease tracking and inspection API
- Revocation with runtime enforcement
- 12 new capability store tests
- Live verification confirmed revocation enforcement works
- Comprehensive documentation

### Branch
- `phase-54-capability-revocation` from `phase-53-policy-recovery`

### Suggested Commits
1. `feat(capabilities): add lease store and tracking`
2. `feat(runtime): enforce revocation in evaluator`
3. `feat(events): add capability tracked/revoked events`
4. `test(capabilities): add store tests`
5. `docs(runtime): document capability lease management`
6. `docs(build): finalize phase 54 checkpoint`

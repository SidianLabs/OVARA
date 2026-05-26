# Phase 56 Capability Governance — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-56-capability-governance`
**Parent**: `phase-55-durable-leases` (commits `4f3cf72`, `67d4e04`)
**Commit**: `8ac71da` feat(capabilities): add durable lease history, governance controls, and delegation visibility
**Objective**: Durable lease history, delegation-chain visibility, and capability governance controls

---

## 1. Repository Verification

- **Current branch**: `phase-56-capability-governance`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Latest commit**: `8ac71da` feat(capabilities): add durable lease history, governance controls, and delegation visibility
- **Parent commits**: `67d4e04`, `4f3cf72` (Phase 55)

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_56_capability_governance_checkpoint.md`
- **Updated**: Full implementation summary
- **Completed**: All 5 milestones
- **Commands run**: `go build ./...`, `go test ./...`, real smoke test with restart

---

## 3. Implementation Summary

### Milestone A: Durable Lease History ✓

**Created `internal/capabilities/file_history_store.go`**:
- `FileBackedHistoryStore` — JSONL append-only, loads on startup, survives restart
- Synchronous write + fsync on every append
- Bounded memory with `maxRecords` (default 50000)
- Methods: Append, ListByLeaseID, ListRecent, ListBySubject, Count, Clear, Close, Stats
- 8 new tests: AppendAndPersist, ReloadOnRestart, ListRecent, ListBySubject, Stats, UsedEntryWithContext, Close, ReloadWithContext

**Config changes**:
- Added `CapabilitiesHistoryFile string` to `config.Config`
- Default: `var/data/capabilities_history.jsonl`
- `main.go` wires `FileBackedHistoryStore` when configured

### Milestone B: Delegation-Chain Visibility ✓

**Enriched `LeaseHistoryEntry`**:
- Added `Action` and `Resource` fields
- `used` events now record action_type and resource used at runtime

**Richer `RevocationChecker.Touch` interface**:
- `Touch(leaseID, action, resource)` passes action/resource context from evaluator
- `capability.used` events now include action and resource

### Milestone C: Lease Governance Controls ✓

**New endpoint: `POST /v1/capabilities/revoke-by-subject`**:
- Bulk revoke all active leases for a given subject
- Returns revoked_count, lease_ids, not_found_count
- Each revoked lease emits history entry and event with `bulk: true` flag

**Extended `GET /v1/capabilities` filters**:
- `?status=active` — only non-revoked, non-expired leases
- `?status=revoked` — only revoked leases
- `?status=all` — all leases (default)
- `?subject=X` and `?issuer=Y` filters remain

### Milestone D: Correlation and Auditability ✓

- `Touch` passes action/resource context → richer audit trail
- `capability.used` events include action + resource
- Bulk revoke events include `bulk: true` flag for filtering
- History entries include subject/issuer on track/revoke

### Milestone E: Docs and Verification ✓

**Documentation updated**:
- `docs/developer/runtime_examples.md` — added revoke-by-subject, status filter, history file config, action/resource in used events
- Capability lease section fully updated for Phase 56

**Tests**: 39 capabilities tests passing

---

## 4. Live Smoke Test Results

Started gateway with `capabilities_history_file: /tmp/ovara56b_test/history.jsonl`:

```
=== Track capability ===
history.jsonl: 1 line
{"lease_id":"cap_56_001","event":"tracked",...}

=== Revoke by subject ===
{"subject":"agent-gov","revoked_count":1,"lease_ids":["cap_56_001"],"not_found_count":0}

=== History file after revoke ===
2 lines: tracked + revoked ✓

=== Kill server ===
=== History file preserved (still 2 lines) ✓

=== After restart: history endpoint ===
{"entries":[{tracked...},{revoked...}],"count":2} ✓

=== Status filter: revoked ===
Returns revoked lease with correct revocation_reason ✓
```

---

## 5. Files Created/Modified

### Created
- `runtime/gateway/internal/capabilities/file_history_store.go` — durable history store
- `runtime/gateway/internal/capabilities/file_history_store_test.go` — 8 persistence tests
- `docs/build/phase_56_capability_governance_checkpoint.md` — this checkpoint

### Modified
- `runtime/gateway/internal/capabilities/store.go` — added Action/Resource to LeaseHistoryEntry
- `runtime/gateway/internal/handlers/capabilities.go` — revoke-by-subject, status filter, action/resource context
- `runtime/gateway/internal/evaluator/evaluator.go` — Touch now passes action/resource
- `runtime/gateway/internal/config/config.go` — added CapabilitiesHistoryFile
- `runtime/gateway/cmd/server/main.go` — wires FileBackedHistoryStore, close on shutdown
- `docs/developer/runtime_examples.md` — governance endpoints, status filter, history durability docs

---

## 6. Git Workflow

- **Branch**: `phase-56-capability-governance` from `phase-55-durable-leases`
- **Commits**: 1 commit
  - `8ac71da` feat(capabilities): add durable lease history, governance controls, and delegation visibility

---

## 7. Validation

### Tests Added/Updated
- `file_history_store_test.go`: 8 tests (AppendAndPersist, ReloadOnRestart, ListRecent, ListBySubject, Stats, UsedEntryWithContext, Close, ReloadWithContext)

### All Tests Passing
```
ok  ovara.runtime.gateway/internal/capabilities  0.786s
ok  ovara.runtime.gateway/internal/evaluator    1.433s
ok  ovara.runtime.gateway/internal/handlers     0.973s
ok  ovara.runtime.gateway/internal/events        (cached)
ok  ovara.runtime.gateway/internal/config        0.996s
(all packages: ok)
```

### Real Flows Verified
- Track → history file has 1 line ✓
- Revoke by subject → history file has 2 lines ✓
- History survives server kill ✓
- After restart: history endpoint returns persisted entries ✓
- Status filter: revoked/active works ✓

---

## 8. What's Intentionally Not Implemented

- **Distributed history sync**: Each gateway maintains its own history file
- **Automatic history cleanup**: File grows indefinitely (no compaction)
- **Cross-gateway governance**: Bulk revoke only affects local gateway
- **Federated identity**: Out of scope

---

## 9. Residual Risks

- **History file grows unbounded**: JSONL append-only with no compaction
- **Per-gateway history**: No centralized audit view across gateways
- **Bulk revoke race**: If new leases are tracked for same subject during bulk revoke, won't be caught

---

## 10. Merge Recommendation

**Ready to merge.**

Phase 56 is complete with:
- Durable lease history (JSONL, survives restart, action/resource context)
- Governance controls (bulk revoke-by-subject, status filter)
- Richer delegation visibility (action/resource in used events)
- 8 new file history store tests (39 total capabilities tests passing)
- Real smoke test confirmed: history persists across restart
- Comprehensive documentation updated

**Single coherent commit** on `phase-56-capability-governance` from `phase-55-durable-leases`.

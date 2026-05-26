# Phase 55 Durable Leases — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-55-durable-leases`
**Parent**: `phase-54-capability-revocation` (commit `599a2b0`)
**Commit**: `4f3cf72` feat(capabilities): add file-backed lease store with persistence, lifecycle history, and delegation visibility
**Objective**: Make delegated authority durable and inspectable — lease persistence, history, and visibility

---

## 1. Repository Verification

- **Current branch**: `phase-55-durable-leases`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Latest commit**: `4f3cf72` feat(capabilities): add file-backed lease store with persistence, lifecycle history, and delegation visibility
- **Parent commit**: `599a2b0` feat(capabilities): add lease tracking, revocation, and runtime enforcement (Phase 54)

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_55_durable_leases_checkpoint.md`
- **Updated**: Complete implementation summary with all milestones
- **Completed work**: All 5 milestones completed
- **Commands run**: `go build ./...`, `go test ./...`, real smoke test with server restart

---

## 3. Implementation Summary

### Milestone A: Lease Persistence ✓

**Created `internal/capabilities/file_store.go`**:
- `FileBackedStore` wrapping in-memory map with JSON file persistence
- Auto-creates parent directory on startup
- Loads all leases from file on startup
- Persists on every `Track`, `Revoke`, `Touch`, and `Clear` operation
- Configurable `maxSize` with oldest eviction when exceeded
- 9 new tests: TrackAndPersist, ReloadOnRestart, RevokeAndReload, ListActiveAfterReload, Stats, ReloadRevokedStillDenies, EvictOldest, Clear, NotFound

**Config changes**:
- Added `CapabilitiesFile string` and `CapabilitiesMaxSize int` to `config.Config`
- Defaults: `var/data/capabilities.json`, max 10000 leases
- `main.go` wires `FileBackedStore` when `CapabilitiesFile` is configured, falls back to `InMemoryStore`

### Milestone B: Lease Lifecycle and History ✓

**Enriched `TrackedLease`**:
- Added `LastSeenAt *time.Time` — updated each time a lease is used at runtime

**New `internal/capabilities/history.go`**:
- `LeaseHistoryEntry` model: LeaseID, Event, Timestamp, GatewayID, Reason, Subject, Issuer
- `HistoryStore`: append-only event log with `ListByLeaseID`, `ListRecent`, `ListBySubject`
- `MaxHistoryEntries = 10000` — bounded in-memory store
- Helper constructors: `LeaseTrackedEntry`, `LeaseUsedEntry`, `LeaseRevokedEntry`
- 8 new tests

### Milestone C: Delegation Visibility ✓

**API improvements**:
- `GET /v1/capabilities?subject=X&issuer=Y` — filter by subject and/or issuer
- `GET /v1/capabilities/{id}` — now returns `{"lease": {...}, "history": [...]}` with lease lifecycle history
- `GET /v1/capabilities/history` — new endpoint for recent lease lifecycle events (up to 500)
- `FileBackedStore.Stats()` returns (total, active, revoked) counts

### Milestone D: Runtime and Audit Correlation ✓

**Runtime enforcement**:
- Added `Touch(leaseID string)` to `RevocationChecker` interface
- Evaluator calls `Touch()` on every valid lease use (after revocation check, before validation)
- `Touch()` updates `LastSeenAt` on the tracked lease
- `Touch()` appends `LeaseUsedEntry` to history store
- `Touch()` emits `capability.used` event to event store

**Events added**:
- `capability.used` — emitted when a lease is validated and used at runtime

### Milestone E: Docs and Verification ✓

**Documentation updated**:
- `docs/developer/runtime_examples.md` — updated capability section with persistence config, history endpoint, filtering, LastSeenAt, restart behavior
- Removed "In-memory only" and "No persistent lease state" limitations
- Added "Capability Lease Persistence" section with config example

**Tests added**:
- `file_store_test.go`: 9 tests for persistence, reload, revocation, eviction
- `history_test.go`: 8 tests for lifecycle tracking
- Total capabilities tests: 30 passing (12 existing + 9 filestore + 9 history)

---

## 4. Live Smoke Test Results

Started gateway with `capabilities_file: /tmp/ovara_test/capabilities.json`:

```
=== Track capability ===
POST /v1/capabilities/track → {status: "tracked", lease_id: "cap_smoke_001"}
capabilities.json created (425 bytes)

=== Revoke capability ===
POST /v1/capabilities/revoke → {status: "revoked", revoked_reason: "smoke test revocation"}

=== Kill server, restart ===
=== After restart: list ===
active_count: 0, revoked_count: 1 ✓ (revocation persisted)

=== After restart: get specific ===
lease with history: tracked + revoked events ✓

=== History endpoint ===
entries: [tracked, revoked] with correct metadata ✓
```

---

## 5. Files Created/Modified

### Created
- `runtime/gateway/internal/capabilities/file_store.go` — file-backed lease store
- `runtime/gateway/internal/capabilities/file_store_test.go` — 9 persistence tests
- `runtime/gateway/internal/capabilities/history.go` — lifecycle history store
- `runtime/gateway/internal/capabilities/history_test.go` — 8 history tests
- `docs/build/phase_55_durable_leases_checkpoint.md` — this checkpoint

### Modified
- `runtime/gateway/internal/capabilities/store.go` — added LastSeenAt, Touch method, history types
- `runtime/gateway/internal/handlers/capabilities.go` — history store, history endpoint, filtering, enriched responses
- `runtime/gateway/internal/evaluator/evaluator.go` — Touch called on lease use, RevocationChecker interface extended
- `runtime/gateway/internal/events/store.go` — added capability.used event type
- `runtime/gateway/internal/config/config.go` — added CapabilitiesFile and CapabilitiesMaxSize
- `runtime/gateway/cmd/server/main.go` — wires FileBackedStore with in-memory fallback
- `docs/developer/runtime_examples.md` — updated capability lease documentation

---

## 6. Git Workflow

- **Branch**: `phase-55-durable-leases` from `phase-54-capability-revocation`
- **Commits**: 1 commit
  - `4f3cf72` feat(capabilities): add file-backed lease store with persistence, lifecycle history, and delegation visibility

---

## 7. Validation

### Tests Added/Updated
- `file_store_test.go`: 9 tests (TrackAndPersist, ReloadOnRestart, RevokeAndReload, ListActiveAfterReload, Stats, ReloadRevokedStillDenies, EvictOldest, Clear, NotFound)
- `history_test.go`: 8 tests (Append, ListRecent, ListBySubject, Count, Clear, LeaseHistoryEntry fields, LeaseRevokedEntry, LeaseUsedEntry)
- `store.go`: added Touch to InMemoryStore, history types

### All Tests Passing
```
ok  ovara.runtime.gateway/internal/capabilities  0.656s
ok  ovara.runtime.gateway/internal/evaluator    1.451s
ok  ovara.runtime.gateway/internal/handlers     2.519s
ok  ovara.runtime.gateway/internal/events        1.884s
ok  ovara.runtime.gateway/internal/config        1.093s
```

### Real Flows Verified
- Track lease → file created ✓
- Revoke lease → revocation reason persisted to file ✓
- Restart gateway → lease reloaded, revoked state preserved ✓
- History endpoint → tracked + revoked events shown ✓
- Get specific lease → lease + history in response ✓

---

## 8. What's Intentionally Not Implemented

- **Persistent history store**: History is in-memory only, resets on restart
- **Distributed lease state**: Each gateway maintains its own file
- **Automatic lease cleanup**: Expired leases remain until explicit revocation or max size eviction
- **Cross-gateway revocation propagation**: Revoking on one gateway doesn't affect another
- **Lease size compaction**: File grows indefinitely (no compaction/snapshot)
- **Federated identity**: Out of scope

---

## 9. Residual Risks

- **History lost on restart**: Only lease state is persisted, history events are in-memory
- **File grows unbounded**: No compaction strategy for the JSON file
- **No distributed synchronization**: Multi-gateway deployments have independent lease state
- **LastSeenAt persisted but may be stale**: Loaded from file on restart but not re-touched

---

## 10. Merge Recommendation

**Ready to merge.**

Phase 55 is complete with:
- File-backed lease store with JSON persistence (survives restart)
- Lease lifecycle history tracking (tracked/used/revoked events)
- LastSeenAt tracking on each lease use
- Delegation visibility improvements (filtering, history endpoint, enriched responses)
- 17 new tests (9 file store + 8 history) all passing
- Real smoke test confirming persistence + revocation survives restart
- Comprehensive documentation updated

**Single coherent commit** on `phase-55-durable-leases` from `phase-54-capability-revocation`.

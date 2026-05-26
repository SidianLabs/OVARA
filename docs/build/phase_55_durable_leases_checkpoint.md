# Phase 55 Durable Leases — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-55-durable-leases`
**Parent**: `phase-54-capability-revocation` (commit `599a2b0`)
**Objective**: Make delegated authority durable and inspectable — lease persistence, history, and visibility

---

## 1. Repository Verification

- **Current branch**: `phase-55-durable-leases` (freshly created)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Parent commits reviewed**:
  - `599a2b0` feat(capabilities): add lease tracking, revocation, and runtime enforcement (Phase 54)
  - `60cac32` feat(policy): add local policy history, rollback, and restore workflow (Phase 53)

---

## 2. Current State Audit

### What's Implemented (Phase 54 baseline)
- `capabilities.InMemoryStore` — in-memory-only, lost on restart
- `TrackedLease` with: Lease, CreatedAt, RevokedAt, RevocationReason, GatewayID
- Revocation enforcement in evaluator before policy evaluation
- Events: `capability.tracked`, `capability.revoked`
- No lease persistence, no history beyond current state, no file-backed storage

### What's Missing (Phase 55 goals)
- Lease state lost on gateway restart
- No lease history or lifecycle audit surface
- Limited delegation visibility (only raw lease listing)
- No cross-object correlation (leases ↔ executions/continuations)
- No file-backed storage path configuration

---

## 3. Implementation Plan

### Milestone A: Lease Persistence
- [ ] Add `FileStore` implementation wrapping `InMemoryStore` with JSON file persistence
- [ ] Storage path configurable via config
- [ ] Load on startup, save on every write operation
- [ ] Keep in-memory store as fallback or remove if FileStore replaces it
- [ ] Add tests for create/revoke/reload behavior

### Milestone B: Lease Lifecycle and History
- [ ] Enrich `TrackedLease` with additional fields (LastSeen, UpdatedAt, HistoryEvents)
- [ ] Add history surface: `GET /v1/capabilities/history`
- [ ] Add `TrackedLeaseHistory` entry type for lifecycle transitions
- [ ] Tests for lifecycle transitions

### Milestone C: Delegation Visibility
- [ ] Improve `GET /v1/capabilities` with delegation depth, scope summary, active/revoked counts
- [ ] Improve `GET /v1/capabilities/?id=` with richer lease metadata
- [ ] Add `subject`, `issuer` filtering on list endpoint
- [ ] Add delegation chain inspection if `DelegationDepth > 0`

### Milestone D: Runtime and Audit Correlation
- [ ] Add `LastUsedAt` / `LastSeenAt` tracking on lease use
- [ ] Emit events when lease is used at runtime
- [ ] Store last-using operation metadata on lease
- [ ] Cross-reference with continuations/executions in event emission

### Milestone E: Docs and Verification
- [ ] Update checkpoint
- [ ] Run tests
- [ ] Real restart + revocation smoke test if feasible

---

## 4. Execution Log

_(to be filled as work progresses)_

---

## 5. Files to Create/Modify

### Create
- `runtime/gateway/internal/capabilities/filestore.go` — file-backed store
- `runtime/gateway/internal/capabilities/filestore_test.go` — persistence tests
- `runtime/gateway/internal/capabilities/history.go` — lease history model
- `runtime/gateway/internal/capabilities/history_test.go` — history tests
- `docs/build/phase_55_durable_leases_checkpoint.md` — this file

### Modify
- `runtime/gateway/internal/capabilities/store.go` — may need interface tweaks
- `runtime/gateway/internal/handlers/capabilities.go` — add history endpoint, improve listing
- `runtime/gateway/cmd/server/main.go` — wire FileStore, configurable storage path
- `runtime/gateway/internal/evaluator/evaluator.go` — track LastSeen on use
- `runtime/gateway/internal/events/store.go` — add lease.used event if beneficial
- `docs/developer/runtime_examples.md` — document durable lease workflow
- `docs/api/delegated_capabilities.md` — update with persistence info

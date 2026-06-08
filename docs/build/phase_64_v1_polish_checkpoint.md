# Phase 64 V1 Polish — Checkpoint

**Branch:** `phase-64-v1-polish`
**Date:** 2026-06-08
**Status:** Complete — all EPIC 1-5 work landed, docs reconciled, tests passing under `-race`

## Completed Commits on This Branch

```
929c03f docs(runtime): reconcile README, SUPPORT_MATRIX, and TROUBLESHOOTING with current implementation
cc6b8ce feat(continuation): StateExecuting claim model, stuck-executing recovery, SLA executing diagnostics
```

## Root Issue Fixed

The uncommitted `StateExecuting` change introduced a race-safe transient claim state but was incomplete — the orchestrator claimed continuations into `StateExecuting` and then immediately called `CanExecute()` which rejected that state, silently dropping every claimed continuation. The direct `handleExecute` path bypassed claim semantics entirely, creating a race with the orchestrator.

## Changes Summary

### Round 1 — `StateExecuting` Claim Model Integration (`cc6b8ce`)

**`continuation/store.go`** (605 lines):
- Added `StateExecuting` — transient claim guard (never a resting state)
- Added `MarkExecutionFailed()` — `StateExecuting` → `StateExecuted` for retry
- Added `MarkRequeue()` — `StateExecuting` → `StateQueued` for SKIP no executor
- Added `LastSkippedAt` field for debouncing repeated SKIP attempts
- Updated `ClaimForExecution()` to accept `StateApproved` as valid source
- Updated `CanExecute()` to accept `StateApproved`; rejects `StateExecuting`
- Updated `IsExecutable()` to reject `StateExecuting`
- Added `RetryInfo()` case for `StateExecuting` → status `"in_progress"`
- Added `RecoverFromExecuting()` + `ListExecutingIDs()` to `Store` interface
- Added `InMemoryStore` implementations for both
- Fixed `Get()` to return `snapshot()` copy (race fix)

**`continuation/orchestrator.go`** (396 lines):
- Removed dead `CanExecute()` guard after `ClaimForExecution`
- Uses `MarkExecuted()`/`MarkExecutionFailed()`/`MarkRequeue()` for all transitions
- Added `sweepStuckExecuting()` on `Start()` — recovers orphaned `executing` continuations
- Added `SetStuckExecutingSweep()` — periodic age-gated stuck-executing recovery
- Added `sweepStuckExecutingThreshold()` — periodic sweep with configurable threshold
- Added `RecoverAllExecuting()` — operator-driven recovery
- Added `ExecutingCount()` + `OldestExecutingAt()` for runtime status observability
- SKIP no executor path debounced via `LastSkippedAt`

**`handlers/continuations.go`** (1237 lines):
- `handleExecute` now uses `ClaimForExecution` atomically instead of manual state mutation
- Uses `MarkExecuted()`/`MarkExecutionFailed()`/`MarkRequeue()` for post-execution transitions
- Added `handleRecoverExecuting` — bulk recovery with `dry_run` + `older_than_minutes` filter
- Added `handleRecoverExecutingItem` — per-item recovery
- Register routes for both recovery endpoints

**`handlers/runtime.go`** (1245 lines):
- Added `executingCount` + `oldestExecutingAt` to continuation stats in `/v1/runtime/status`
- Added top-level `executing` + `oldest_executing_at` via orchestrator
- Added `executing_breaching` SLA count + `executing_threshold_min` threshold
- SLA section now includes executing breach diagnostics

**`config/config.go`**:
- Added `StuckExecutingSweepIntervalSec`, `StuckExecutingRecoveryThresholdMin`
- Added `SLAExecutingMaxAgeMin` (default: 5 min)

**`cmd/server/main.go`**:
- Wires `SetStuckExecutingSweep` on orchestrator startup

**`continuation/file_store.go`** (558 lines):
- Added `ClaimForExecution`, `ClaimForRetry` with inline persistence
- Added `RecoverFromExecuting` with inline persistence
- Added `ListExecutingIDs`
- `RetryForExecution` and `CancelForOperation` persist inline

**Tests** (317+ new lines):
- `store_test.go`: 12 new tests for `StateExecuting`, `MarkExecutionFailed`, claim rejection
- `file_store_test.go`: 8 new tests for claim/retry/recover in file-backed store
- `orchestrator_test.go`: 3 new tests for startup sweep + idempotency
- `retry_info_test.go`: 1 new test for `StateExecuting` RetryInfo
- `execution_test.go`: 4 test expectations updated; retry-after-failure test rewritten
- `runtime_sla_test.go`: SLA executing_breaching tests
- `checker_test.go`: updated mock store interfaces with new methods

### Round 2 — Documentation Reconciliation (`929c03f`)

**`runtime/gateway/README.md`**:
- Added `git.fetch` and `git.checkout` to action types list
- Added `QUEUE`, `RECOVER stuck-executing`, `RECOVER executing` log prefixes

**`runtime/gateway/SUPPORT_MATRIX.md`**:
- Corrected continuation states table (added `executing`, documented `ready` as legacy)
- Corrected claim methods table (target state `executing`, not `ready`; added `approved` as valid source)
- Added `RecoverFromExecuting` to claim methods
- Corrected state transition diagrams
- Added `RECOVER` log prefixes

**`runtime/gateway/TROUBLESHOOTING.md`**:
- Added `RECOVER stuck-executing`, `RECOVER stale-executing`, `RECOVER executing` log prefixes

## Final Continuation State Model

```
escalated → approved → queued → [ClaimForExecution] → executing
             ↓ (direct)       → [ClaimForExecution] → executing
resumed      → [ClaimForExecution] → executing

executing → MarkExecuted()          → executed
executing → MarkExecutionFailed()   → executed  (retryable)
executing → MarkRequeue()           → queued    (SKIP no executor)
executing → RecoverFromExecuting()  → executed  (operator recovery)

executed → RetryForExecution → resumed → ... (retry loop)
queued/ready/resumed → CancelForOperation → cancelled
```

**Key property:** `executing` is transient — only one path holds it at a time. On gateway restart, the startup sweep recovers all orphaned `executing` continuations to `executed`. Operators can force-recover via `POST /v1/continuations/recover-executing`.

## Operator Recovery Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/continuations/recover-executing?dry_run=true` | Enumerate stuck executing items |
| `POST /v1/continuations/recover-executing?older_than_minutes=N` | Recover items older than N minutes |
| `POST /v1/continuations/recover-executing` | Recover all executing items |
| `POST /v1/continuations/{id}/recover-executing` | Recover a single executing item |

## SLA Diagnostics

| Config Key | Default | What It Tracks |
|------------|---------|----------------|
| `sla_approval_max_age_min` | 30 | Pending approvals older than threshold |
| `sla_retryable_max_age_min` | 60 | Retryable continuations older than threshold |
| `sla_executing_max_age_min` | 5 | Continuations in `executing` older than threshold |
| `stuck_executing_sweep_interval_secs` | 0 (disabled) | Periodic stuck-executing recovery sweep |
| `stuck_executing_recovery_threshold_min` | 30 | Minimum age before periodic sweep recovers |

## Validation

```
go test ./...              → 22/22 packages passing
go test -race ./...        → 22/22 packages passing
go vet ./...               → clean
go build ./...             → clean
```

Source files: 53 (excluding tests). Test files: 62. Total test functions: ~300+.

## Remaining Risks / Follow-ups

1. **`ready` state is now legacy.** All claim paths use `executing`, but `ready` still exists in the state machine. `MarkReady()` and `IsReady()` are still present but unused by active paths. Could be safely removed in a follow-up with minor downstream impact (status endpoints that report `by_state` would lose the `ready` key).

2. **No panic recovery in executeOne.** If an executor panics, the continuation stays in `executing` forever until a restart or operator recovery. A deferred `recover()` with `MarkExecutionFailed()` would make this resilient (low priority — executors in practice don't panic).

3. **Health endpoint doesn't surface executing breaching.** The `/v1/runtime/health` SLA object currently shows `approvals_breaching` and `retryable_breaching` but not `executing_breaching`. The `/v1/runtime/status` endpoint already includes it. Minor consistency gap.

4. **Other directories (`cloud/`, `identity/`, `sdk/`, etc.) are scaffolded but empty.** This is consistent with Phase 1 scope. The only active code is in `runtime/gateway/`, with interceptors in `interceptors/`.

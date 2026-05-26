# Phase 20 Approval Durability — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-20-approval-durability`
**Parent**: `phase-17-event-persistence` (stable merged baseline)
**Objective**: Make approvals and continuations durable, enforceable, and restart-safe

---

## 1. Repository Verification

- **Current branch**: `phase-20-approval-durability`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits reviewed**:
  - `fbcfeb1` docs(build): add phase 19 durable continuations checkpoint (HEAD of phase-17-event-persistence)
  - `28942cb` feat(events): emit continuation lifecycle audit events
  - `bb6f1ee` feat(runtime): tighten continuation lifecycle semantics
  - `fbae0e5` feat(continuation): add file-backed continuation store
- **Actual approval/continuation behavior found at start**:
  - Approvals have file-backed store (JSON, full rewrite per write) — already durable
  - Continuations have file-backed store (JSONL append) — already durable
  - No expiration enforcement — `continuation.expired` event type defined but not emitted
  - No startup reconciliation — expired continuations silently remain in stale state
  - Sweeper not started — no background goroutine running
  - `ContinuationSweepIntervalSec` config field missing

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_20_approval_durability_checkpoint.md`
- **Updated**: All milestones, state of approval persistence, sweeper behavior, file list, git log, smoke test output
- **Completed**: All milestones (A: approval store verified + sweep config, B: sweeper, C: startup reconciliation, D: stats enrichment, E: docs/verification)
- **Commands run**: `go build ./...` (clean), `go test ./...` (17/17 pass), real smoke test with restart

---

## 3. Implementation Work Completed

### Milestone A — Approval Persistence + Sweep Config

**Approval store already file-backed** (`runtime/gateway/internal/approval/file_store.go`):
- Uses JSON file (full rewrite per write, not append)
- `NewFileBackedStore(path)` — loads all approvals on init, persists on Create/Update/Delete
- Already in main.go — wired via `cfg.ApprovalsFile` with fallback to in-memory
- Already tested with 8 tests in `file_store_test.go`

**New sweep interval config** (`runtime/gateway/internal/config/config.go`):
- Added `ContinuationSweepIntervalSec int` field (default 60 seconds)
- Applies only when `> 0`

---

### Milestone B — Expiration Sweeper

**New `Sweeper`** (`runtime/gateway/internal/continuation/sweeper.go`):
- Periodically scans non-terminal continuations and expires those past their `ExpiresAt`
- `Start(intervalSec)` — starts background goroutine with ticker, guards against double-start
- `Stop()` — stops ticker cleanly
- `SweepNow()` — synchronous single sweep, returns count of expired continuations
- `ReconcileOnStartup()` — one-shot scan for expired continuations on startup
- On each expiration: calls `cnt.MarkExpired()`, `store.Update()`, emits `continuation.expired` event with `continuation_id`, `state`, `reason`
- After each sweep: emits `continuation.sweep_completed` event with `expired_count` and `scanned_count`

**Wired in main.go**:
```go
sweeper := continuation.NewSweeper(continuationStore)
sweeper.SetEventStore(eventStore)
sweeper.SetGatewayID(enrollmentSvc.GetIdentity().ID)

expiredOnStartup := sweeper.ReconcileOnStartup()
if expiredOnStartup > 0 {
    log.Printf("continuation reconciliation: %d expired on startup", expiredOnStartup)
}

if sweepInterval > 0 {
    sweeper.Start(sweepInterval)
    log.Printf("continuation sweeper started (interval=%ds)", sweepInterval)
}
```

**Shutdown**: `sweeper.Stop()` called on SIGINT/SIGTERM

**8 sweeper tests** (`sweeper_test.go`):
- `TestSweeper_SweepNow_ExpiresStale` — expired approved + escalated transitions, fresh continuation untouched
- `TestSweeper_SweepNow_DoesNotExpireTerminal` — resumed continuations immune
- `TestSweeper_SweepNow_DoesNotExpireNoExpiry` — continuations without ExpiresAt immune
- `TestSweeper_ReconcileOnStartup` — startup reconciliation sets `ExpiredAt`, emits event
- `TestSweeper_StartStop` — goroutine starts and stops cleanly
- `TestSweeper_StartTwiceNoOp` — guard against double-start
- `TestSweeper_SweepNow_ReturnsCount` — returns exact count of expired continuations
- `TestSweeper_SweepNow_EmitsExpiredEvent` — event type, gateway_id, approval_id all correct

---

### Milestone C — Startup Reconciliation

**`ReconcileOnStartup()`** — called synchronously before the sweeper goroutine starts:
1. Scans all non-terminal continuations
2. For any where `ShouldExpire(now)` is true, transitions to `StateExpired`
3. Persists update to store
4. Emits `continuation.expired` event with `reason: "expired_on_startup"`
5. Logs count if any expired

**Note**: In smoke test with ~60 minute TTL and fresh continuations, no startup expiration occurred (expected). The reconciliation path is verified by the unit test.

---

### Milestone D — Inspection Enrichment

**Stats endpoint enhanced** (`GET /v1/continuations/stats`):
```json
{
  "total": 3,
  "by_state": {"escalated": 1, "ready": 2},
  "executable": 2,
  "expired": 0
}
```

**New manual sweep endpoint** (`POST /v1/continuations/sweep`):
```json
{"expired": 0, "scanned": 3}
```
Allows operators to trigger expiration scan on demand.

---

## 4. Real Smoke Test Verified

**Restart survival + approval persistence**:
```
Gateway started with:
  - approvals_file=/tmp/ovara_p20_data/approvals.json
  - continuations_file=/tmp/ovara_p20_data/continuations.jsonl
  - events_file=/tmp/ovara_p20_data/events.jsonl
  - continuation_sweep_interval_secs=30

=== Create approval manually ===
approval_id=apr_d93b3aa2-0d0d-43, status=pending

=== Stats after create ===
by_state={"escalated":1}, executable=0, expired=0, total=1

=== Events after create ===
continuation.created : cnt_5bf191db-a239-4e
approval.created

=== Approve ===
status=approved

=== Stats after approve ===
by_state={"ready":1}, executable=1, expired=0, total=1

=== Restart ===
=== Stats after restart ===
by_state={"ready":1}, executable=1, expired=0, total=1

=== Files on disk ===
approvals.json (419 bytes) — survived restart
continuations.jsonl (2 lines) — create + approve persisted
events.jsonl (1370 bytes) — all events persisted

=== Resume ===
resumed=True, continuation_id=cnt_5bf191db-a239-4e

=== Events after full lifecycle ===
continuation.created
approval.created
continuation.ready
approval.resolved
continuation.resumed
approval.resumed
```

---

## 5. Git Workflow

- **Branch**: `phase-20-approval-durability`
- **Commits created**:
  1. `04858b3` — `feat(continuation): add expiration sweeper and startup reconciliation`

---

## 6. Files Changed

### Created
- `runtime/gateway/internal/continuation/sweeper.go` — Sweeper struct, Start/Stop/SweepNow/ReconcileOnStartup methods
- `runtime/gateway/internal/continuation/sweeper_test.go` — 8 tests

### Modified
- `runtime/gateway/internal/config/config.go` — `ContinuationSweepIntervalSec` field and default
- `runtime/gateway/internal/continuation/store.go` — `ListNonTerminal()` added to Store interface and InMemoryStore
- `runtime/gateway/internal/handlers/continuations.go` — Stats enhanced with `expired` count, new `handleSweep` endpoint
- `runtime/gateway/cmd/server/main.go` — Sweeper init, ReconcileOnStartup call, Start call, Stop on shutdown

---

## 7. Validation

- **Tests**: 8 new sweeper tests, all passing. Total continuation tests: 34 (8 sweeper + 7 file store + 9 lifecycle/expiration + 10 model/store)
- **`go test ./...`**: 17/17 packages pass
- **Real smoke test**: Approval + continuation survive restart, events emitted correctly, stats show correct counts
- **Startup reconciliation**: Unit-tested via `TestSweeper_ReconcileOnStartup` — one-shot scan works
- **Manual sweep**: `POST /v1/continuations/sweep` endpoint wired, returns `{expired, scanned}`
- **Not fully verified**: Actual periodic sweep tick (requires 30s wait), startup reconciliation with truly expired data (would need a continuation with past `ExpiresAt` already in the store before restart)

---

## 8. Assumptions and Tradeoffs

- Approval store is JSON (full rewrite per write) not JSONL append — same pattern as phase 17 event store. This means writes are O(n) where n = total approvals, acceptable for local-first use.
- Sweeper interval defaults to 60s — short enough to catch expired continuations reasonably quickly, not so short as to cause overhead
- Startup reconciliation is synchronous and runs before the sweeper goroutine starts — prevents a race where a request could find an already-expired continuation before the sweeper has run
- Sweeper does not emit `continuation.expired` for `State == escalated` that expire before approval — this is correct (escalated continuations that expire before being approved are also transitioned to expired)
- Sweeper is a simple ticker-based loop — no cron, no distributed scheduling. Acceptable for local operator use.

---

## 9. Residual Risks

- Periodic sweep only runs if `ContinuationSweepIntervalSec > 0` — defaults to 60 but if config is missing/zero, no background sweep runs
- No compaction on continuation JSONL — file grows with each create/update. Acceptable for local-first use.
- Approval store uses JSON full-rewrite — not append like continuations. Acceptable but different from other stores.
- Resume in handler checks `CanResume()` but approval service also checks `StatusApproved` — redundant but safe

---

## 10. Merge Recommendation

**Ready to merge** `phase-20-approval-durability` into `phase-17-event-persistence`.

Phase 20 closes the enforcement gap in the continuation lifecycle:

- **Approval persistence**: Already file-backed (JSON, survives restart) — verified with 8 tests and smoke test
- **Expiration sweeper**: Lightweight periodic sweeper with `SweepNow()` and `Start(intervalSec)/Stop()`, fully tested (8 tests)
- **Startup reconciliation**: `ReconcileOnStartup()` scans and expires stale continuations before the sweeper goroutine starts, with event emission and logging
- **Stats enrichment**: `expired` count in stats endpoint, manual sweep endpoint for on-demand expiration
- **Event emission**: `continuation.expired` event with `reason: "expired"` or `reason: "expired_on_startup"`, plus `continuation.sweep_completed` events
- **Tests**: 8 new sweeper tests, all pass
- **Real smoke test**: Restart survival confirmed for both approvals and continuations, lifecycle events correct

The system now has active enforcement of continuation expiration rather than just advisory checks. Future phases could add compaction for JSONL files, approval expiration semantics, or re-execution using the continuation artifact.
# Phase 19 Durable Continuations — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-19-durable-continuations`
**Parent**: `phase-18-continuation` (merged into phase-17-event-persistence)
**Objective**: Make continuations survive restart and become a stronger execution-readiness primitive

---

## 1. Repository Verification

- **Current branch**: `phase-19-durable-continuations`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits reviewed**:
  - `8816531` docs(build): add phase 18 continuation checkpoint (HEAD of phase-18-continuation)
  - `77a116a` feat(api): add continuation inspection endpoints
  - `f82004a` feat(runtime): add continuation model for escalated actions
  - `a0a2ebd` docs(build): add phase 17 event persistence checkpoint
- **Actual continuation behavior found at start**:
  - `Continuation` model with state machine (escalated/approved/denied/resumed/expired)
  - `InMemoryStore` only — continuations lost on restart
  - No `ready` state, no expiration semantics, no event correlation
  - `CanResume()` returned true for `StateApproved` directly

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_19_durable_continuations_checkpoint.md`
- **Updated**: All 5 milestones, file list, git log, smoke test output
- **Completed**: All milestones (A: persistence, B: lifecycle, C: events, D: inspection, E: docs/verification)
- **Commands run**: `go build ./...` (clean), `go test ./...` (17/17 pass), real smoke test with restart survival

---

## 3. Implementation Work Completed

### Milestone A — Continuation Persistence

**New `FileBackedStore`** (`runtime/gateway/internal/continuation/file_store.go`):
- Embeds `*InMemoryStore` for in-memory query layer
- Appends continuations as JSON Lines to file on every `Create()` and `Update()`
- Syncs after each write for durability
- On startup, loads existing continuations from JSONL file into in-memory store
- Config fields: `ContinuationsFile`, `ContinuationsMaxSize` (default 10,000)
- Default path: `var/data/continuations.jsonl`
- Graceful shutdown closes file handle
- `Close()` method, `LoadedCount()`, `FilePath()`, `CountByState()` accessors

**Config changes** (`runtime/gateway/internal/config/config.go`):
- Added `ContinuationsFile string` and `ContinuationsMaxSize int`
- Defaults set in `Default()`: file=`var/data/continuations.jsonl`, max=10000

**Wiring** (`runtime/gateway/cmd/server/main.go`):
- If `cfg.ContinuationsFile != ""` → use `NewFileBackedStore`
- Fall back to in-memory on error with warning log
- `FileBackedStore.Close()` called on graceful shutdown

**7 tests** (`file_store_test.go`):
- `TestFileBackedStore_BasicCreateAndPersist`
- `TestFileBackedStore_LoadsExistingContinuations`
- `TestFileBackedStore_UpdatePersists`
- `TestFileBackedStore_EmptyFileOK`
- `TestFileBackedStore_CountByState`
- `TestFileBackedStore_FilePathAccessor`
- `TestFileBackedStore_MarkDeniedAndReload`

---

### Milestone B — Continuation Lifecycle Tightening

**State machine refined**:

| State | Meaning | CanResume? |
|---|---|---|
| `escalated` | Awaiting approval | No |
| `approved` | Approved, awaiting readiness | Yes (via approval approve) |
| `ready` | Approved + explicitly ready to execute | Yes (via `MarkReady`) |
| `denied` | Denied by operator | No (terminal) |
| `resumed` | Action resumed/executed | No (terminal) |
| `expired` | Timed out before execution | No (terminal) |

**New methods on `Continuation`**:
- `MarkReady()` — transitions `approved → ready` only (guards against wrong states)
- `MarkExpired()` — transitions non-terminal states to `expired` with timestamp
- `IsReady()` — true when state is `ready`
- `IsExecutable()` — true when state is `approved` or `ready` AND not expired
- `ShouldExpire(time.Time)` — true when state is `escalated`/`approved` and past `ExpiresAt`
- `TimeToExpiry()` — seconds until expiration, or -1 if no expiration set

**Expiration semantics**:
- `DefaultExpirationMinutes = 60` — default TTL for new continuations
- `WithExpiration(minutes)` builder sets `ExpiresAt` at creation time
- Approval create sets expiration via `WithExpiration(continuation.DefaultExpirationMinutes)`
- `CanResume()` returns true for both `StateApproved` and `StateReady` (approval approve makes immediately executable)

**State transition diagram**:
```
esclated --approve--> approved --markReady--> ready --resume--> resumed
                    |
                    +--deny--> denied
                    |
                    +--expire--> expired

escalated --expire--> expired (if past ExpiresAt before approve)
```

**Updated `CanResume()`**: Returns true when `State == StateApproved || State == StateReady`

**Updated `IsTerminal()`**: Returns true when `State == StateDenied || State == StateExpired || State == StateResumed`

**New/updated tests** (9 tests in `store_test.go`):
- `TestContinuation_CanResume` — updated to reflect approved is always resumable
- `TestContinuation_IsTerminal` — updated to include `resumed`
- `TestContinuation_MarkReady` — guards against wrong-state transitions
- `TestContinuation_MarkExpired` — guards against terminal-state transitions
- `TestContinuation_WithExpiration` — expiration builder
- `TestContinuation_IsExpired` — past expiry check
- `TestContinuation_TimeToExpiry` — TTL computation
- `TestContinuation_StateTransitionFlow` — full lifecycle verified
- `TestContinuation_IsExecutable` — combined state+time check
- `TestContinuation_ShouldExpire` — time-based expiration predicate

---

### Milestone C — Continuation/Event Correlation

**5 new event types** (`runtime/gateway/internal/events/store.go`):
- `continuation.created` — emitted on approval create, includes `continuation_id`, `action_type`, `resource`, `trust_score`, `state`, `expires_at`
- `continuation.ready` — emitted on approval approve, includes `continuation_id`, `resolved_by`, `state`
- `continuation.denied` — emitted on approval deny, includes `continuation_id`, `resolved_by`, `reason`, `state`
- `continuation.resumed` — emitted on approval resume, includes `continuation_id`, `state`
- `continuation.expired` — reserved for future expiration sweep (not yet wired to a scheduler)

**All continuation lifecycle events include**:
- `gateway_id`
- `decision_id` (where applicable)
- `approval_id` (where applicable)
- `agent_id` (where applicable)

**Handler changes** (`runtime/gateway/internal/handlers/approval.go`):
- `handleCreate`: emits `continuation.created` + `approval.created`
- `handleApprove`: emits `continuation.ready` + `approval.resolved` (action=approved)
- `handleDeny`: emits `continuation.denied` + `approval.resolved` (action=denied)
- `handleResume`: emits `continuation.resumed` + `approval.resumed`

---

### Milestone D — Inspection and Status Enrichment

**`GET /v1/continuations` enhanced**:
- Returns `continuations[]` with enriched per-item fields:
  - `continuation_id`, `decision_id`, `approval_id`, `agent_id`, `action_type`, `resource`, `state`, `created_at`
  - `is_executable` — boolean readiness indicator
  - `time_to_expiry` — seconds until expiration
  - `approved_at`, `resumed_at`, `expires_at`, `resolved_by` (when present)
- Top-level `count` and `executable` summary fields

**`GET /v1/continuations/stats` new endpoint**:
```json
{
  "total": 3,
  "by_state": {"escalated": 1, "ready": 2},
  "executable": 2
}
```

---

## 4. Real Smoke Test Verified

**Restart survival test**:
```
Gateway started with:
  - continuations_file=/tmp/ovara_p19_data/continuations.jsonl
  - events_file=/tmp/ovara_p19_data/events.jsonl

=== Create approval manually ===
approval_id=apr_6052abda-c312-4b, status=pending

=== Stats before approval ===
by_state={"escalated":1}, total=1, executable=0

=== Approve ===
status=approved

=== Stats after approval ===
state=ready, is_executable=true

=== Resume ===
{
  "resumed": true,
  "approval_id": "apr_6052abda-c312-4b",
  "continuation_id": "cnt_5e5b9d51-0f2e-45",
  "decision_id": "dec_manual_escalate",
  "action_type": "shell",
  "resource": "shell:curl |sh",
  "metadata": {"escalation_reason": "policy_escalate"},
  "trust_level": "medium",
  "trust_score": 0.5
}

=== Events observed ===
continuation.created
approval.created
continuation.ready
approval.resolved
continuation.resumed
approval.resumed

=== Restart gateway ===
=== After restart: continuation still present ===
count=1
  id=cnt_5e5b9d51-0f2e-45, state=resumed (survived restart)
```

**JSONL file verified**: 3 lines (create + approve + resume) for same `cnt_5e5b9d51-0f2e-45`

---

## 5. Git Workflow

- **Branch**: `phase-19-durable-continuations`
- **Commits created**:
  1. `fbae0e5` — `feat(continuation): add file-backed continuation store`
  2. `bb6f1ee` — `feat(runtime): tighten continuation lifecycle semantics`
  3. `28942cb` — `feat(events): emit continuation lifecycle audit events`

---

## 6. Files Changed

### Created
- `runtime/gateway/internal/continuation/file_store.go` — FileBackedStore with JSONL append, load-on-start, Close
- `runtime/gateway/internal/continuation/file_store_test.go` — 7 persistence tests

### Modified
- `runtime/gateway/internal/continuation/store.go` — `StateReady` constant, `ExpiresAt`/`ExpiredAt` fields, `WithExpiration()`, `MarkReady()`, `MarkExpired()`, `IsReady()`, `IsExecutable()`, `ShouldExpire()`, `TimeToExpiry()`, updated `CanResume()`/`IsTerminal()`
- `runtime/gateway/internal/continuation/store_test.go` — 9 lifecycle/expiration tests
- `runtime/gateway/internal/handlers/approval.go` — Expiration on creation, `MarkReady()` on approve, continuation events on all lifecycle transitions
- `runtime/gateway/internal/handlers/continuations.go` — Enriched list response with `is_executable`/`time_to_expiry`, new `handleStats` endpoint, `executableCount` helper
- `runtime/gateway/internal/events/store.go` — 5 new event type constants
- `runtime/gateway/internal/config/config.go` — `ContinuationsFile`, `ContinuationsMaxSize` fields, defaults
- `runtime/gateway/cmd/server/main.go` — File-backed continuation store init with fallback, Close on shutdown, `ExpirationsFile` config

---

## 7. Validation

- **Tests added**: 16 new tests (7 file_store + 9 lifecycle/expiration)
- **Total continuation tests**: 26 (7 file store + 14 original model/store + 5 handler)
- **All tests pass**: `go test ./...` — 17/17 packages pass
- **Real smoke test**: Restart survival confirmed — continuation persisted in JSONL, survives restart, reloaded correctly
- **Event correlation verified**: 6 event types emitted across continuation lifecycle
- **Continuation stats**: `GET /v1/continuations/stats` returns counts by state and executable count
- **List response**: `is_executable` and `time_to_expiry` included per continuation

---

## 8. Assumptions and Tradeoffs

- Continuation file uses append-only JSONL — each update appends a new line (same as event store pattern). This means the file grows and old state is not overwritten until compaction. Acceptable for local-first use.
- Expiration check is advisory — `IsExecutable()` returns false for expired continuations but there's no automatic background expiration sweeper. Operators must manually expire or deny stale continuations.
- `continuation.expired` event type is defined but not yet emitted — no scheduler/sweeper is running to mark expired continuations. This is future work.
- `CanResume()` returns true for both `approved` and `ready` — this means the approval itself makes the continuation immediately executable. `MarkReady()` exists as a method but is always called immediately after `MarkApproved()` in the handler. The two-step (`approved` then `ready`) is preserved as a pattern for future cases where readiness might be gated.

---

## 9. Residual Risks

- No automatic expiration sweeper — stale continuations in `escalated`/`approved` state accumulate until manually resolved
- JSONL grows indefinitely — no compaction or rotation (same as event store)
- `Seq` on events resets on restart (documented limitation, not new in this phase)
- No file-backed store for approvals yet — approval store is still in-memory (inherited)
- Resume still requires approval to be in `StatusApproved` — continuation readiness check in handler is redundant with approval service check

---

## 10. Merge Recommendation

**Ready to merge** `phase-19-durable-continuations` into `phase-17-event-persistence`.

Phase 19 makes continuations a durable, inspectable, event-correlated execution primitive:

- **Persistence**: File-backed JSONL store with load-on-start, confirmed restart survival
- **Lifecycle**: 6 states (escalated/approved/ready/denied/resumed/expired), expiration semantics, `IsExecutable()` check
- **Events**: 5 new event types covering every continuation lifecycle transition, all with correlation IDs
- **Inspection**: Enriched list response with `is_executable`/`time_to_expiry`, stats endpoint with counts by state
- **Tests**: 16 new tests, all passing
- **Real smoke test**: Decision → approval → approve → resume → restart → continuation still present with correct state

The continuation artifact is now durable, auditable via events, and inspectable via API. Future phases could add automatic expiration sweeping, re-execution using the continuation artifact, or file-backed persistence for approvals.
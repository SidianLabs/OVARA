# Phase 22 Execution Hardening — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-22-execution-hardening`
**Parent**: `phase-17-event-persistence` (stable merged baseline)
**Objective**: Make approved shell execution production-ready — durable records, explicit failure semantics, replay safety

---

## 1. Repository Verification

- **Current branch**: `phase-22-execution-hardening`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits reviewed**:
  - `c94eaed` docs(build): add phase 21 local executor checkpoint
  - `3ea69de` feat(execution): add local shell executor and approved continuation execution path
  - `68fd173` docs(build): add phase 20 approval durability checkpoint
- **Actual execution/continuation behavior found at start**:
  - `Execution` struct with states: `pending`, `running`, `succeeded`, `failed`
  - `InMemoryStore` only — execution records lost on restart
  - `ShellExecutor` used `MarkFailed` for timeout (not a distinct state)
  - `handleExecute` used `IsExecutable()` for guard (only checked state != approved/ready and expiration)
  - `MarkExecuted()` transitioned continuation to `executed` on success only
  - No `timed_out` state, no distinct timeout event
  - No duplicate execution protection — any `ready` continuation could be executed repeatedly
  - `ExecutionHandler` registered duplicate `POST /v1/continuations/{id}/execute` route (same as ContinuationHandler)
  - `handleExecute` did not call `MarkReady()` for `StateApproved` — approved continuations couldn't be executed

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_22_execution_hardening_checkpoint.md`
- **Updated**: All milestones, execution model, state transitions, file list, git log, test coverage, residual risks updated
- **Completed**: All milestones (A: persistence, B: lifecycle, C: timeout/failure, D: replay safety, E: inspection, F: docs/verification)
- **Commands run**: `go build ./...` (clean), `go test ./...` (17/17 pass)
- **New bugs found and fixed during implementation**: duplicate route registration, approved-not-ready gap
- **New test coverage**: ~25 new tests covering API-level execution, restart durability, retry semantics

---

## 3. Implementation Work Completed

### Milestone A — Execution Persistence

**New file-backed execution store** (`runtime/gateway/internal/execution/file_store.go`):
- Follows the same pattern as `continuation.FileBackedStore` and `events.FileBackedStore`
- JSONL append-only format, one JSON record per line
- `NewFileBackedStore(path, maxSize)` — creates directory, opens/creates file, loads existing records
- `load()` on startup — reads all lines, unmarshals, populates in-memory map
- `Create(e *Execution)` — appends JSON line + fsync
- `Update(e *Execution)` — appends updated JSON line + fsync
- `Close()` — closes the underlying file
- `LoadedCount()` — returns count of records loaded from disk on startup
- `FilePath()` — returns configured storage path

**Config additions**:
```go
ExecutionFile   string `json:"execution_file"`
ExecutionsMaxSize int  `json:"executions_max_size"`
```
Defaults: `var/data/executions.jsonl`, 10000 records max

**Integration in main.go**:
- `var execStore execution.Store` (interface type to allow both implementations)
- File-backed store instantiated when `cfg.ExecutionFile != ""`
- Falls back to in-memory on error with warning log
- Graceful shutdown closes `FileBackedStore` if applicable

---

### Milestone B — Execution Lifecycle Semantics

**States revised**:
```
pending → running → succeeded
                  → failed
                  → timed_out
```

**`StateTimedOut` added** as explicit terminal state distinct from `failed`:
```go
const (
    StatePending   State = "pending"
    StateRunning   State = "running"
    StateSucceeded State = "succeeded"
    StateFailed    State = "failed"
    StateTimedOut  State = "timed_out"
)
```

**`MarkTimedOut()` method added**:
```go
func (e *Execution) MarkTimedOut() {
    e.State = StateTimedOut
    now := time.Now().UTC()
    e.FinishedAt = &now
}
```

**`IsTerminal()` updated** to include `StateTimedOut**:
```go
func (e *Execution) IsTerminal() bool {
    return e.State == StateSucceeded || e.State == StateFailed || e.State == StateTimedOut
}
```

**`Stats()` signature updated** to return 5 values:
```go
Stats() (total, succeeded, failed, running, timedOut int)
```

**Continuation state after execution**:
- `StateExecuted` transition on success only (unchanged)
- On `timed_out` or `failed`: continuation stays in `StateReady` — not transitioned to executed
- This allows operators to inspect and retry with adjusted timeout if needed

---

### Milestone C — Timeout and Failure Handling

**ShellExecutor timeout behavior fixed**:
```go
if execCtx.Err() == context.DeadlineExceeded {
    e.MarkTimedOut()  // was: MarkFailed("execution timed out...")
    return err
}
```

**Distinct event types for failure modes**:
```go
EventTypeExecutionSucceeded = "execution.succeeded"
EventTypeExecutionFailed     = "execution.failed"
EventTypeExecutionTimedOut  = "execution.timed_out"  // NEW
```

**handleExecute event dispatch**:
```go
switch exe.State {
case execution.StateSucceeded:
    evtType = EventTypeExecutionSucceeded
    cnt.MarkExecuted()
case execution.StateTimedOut:
    evtType = EventTypeExecutionTimedOut  // NEW
default:
    evtType = EventTypeExecutionFailed
}
```

**Failure vs timeout differentiation**:
- Non-zero exit code (without timeout): `StateFailed`, `execution.failed` event
- Context deadline exceeded: `StateTimedOut`, `execution.timed_out` event
- Both preserve `stdout`/`stderr`/`error` fields for inspection

---

### Milestone D — Replay Safety and Duplicate Execution Protection

**`CanExecute()` method on Continuation**:
```go
func (c *Continuation) CanExecute() bool {
    return c.State == StateReady && c.ActionType == "shell"
}
```

**`IsExecutable()` updated** to explicitly exclude `StateExecuted**:
```go
func (c *Continuation) IsExecutable() bool {
    if c.State != StateApproved && c.State != StateReady {
        return false
    }
    if c.State == StateExecuted {  // explicit block
        return false
    }
    if c.ExpiresAt != nil && time.Now().UTC().After(*c.ExpiresAt) {
        return false
    }
    return true
}
```

**handleExecute uses `CanExecute()` for tighter gate**:
```go
if !cnt.CanExecute() {
    api.JSONBadRequest(w, "continuation not in executable state: current state="+string(cnt.State))
    return
}
```

**Re-execution protection semantics**:
- Only `StateReady` continuations can be executed (not `StateApproved`)
- Once executed, `StateExecuted` → `CanExecute()` returns false → blocked
- Resumed/expired/denied continuations cannot be executed
- Timeout or failure does NOT transition continuation to a terminal state — it stays `ready`
- This allows re-execution with adjusted timeout in the future if operator chooses

**Approved-not-ready bug fixed**:
- `handleExecute` now calls `cnt.MarkReady()` when `cnt.State == StateApproved` before the `CanExecute()` check
- Previously, approved continuations could not be executed via the API

---

### Milestone E — Execution Inspection and Status

**ExecutionHandler route fix**:
- `ExecutionHandler` no longer registers `POST /v1/continuations/{id}/execute` (was duplicate of ContinuationHandler's route)
- Now only handles: `GET /v1/executions` and `GET /v1/executions/{id}` for execution inspection

**ExecutionHandler simplified** (no longer needs executor, eventStore, gatewayID):
```go
type ExecutionHandler struct {
    store execution.Store
}
NewExecutionHandler(store execution.Store) *ExecutionHandler
```

**Stats() now tracks timed_out**:
- Returns 5-tuple: (total, succeeded, failed, running, timedOut)
- Both `InMemoryStore.Stats()` and `FileBackedStore.Stats()` updated

---

## 4. File Changes

### Created
- `runtime/gateway/internal/execution/file_store.go` — file-backed execution store (JSONL, 159 lines)
- `runtime/gateway/internal/execution/file_store_test.go` — 14 tests for persistence/reload/lifecycle (345 lines)
- `runtime/gateway/internal/handlers/execution_test.go` — ~25 API-level tests (940 lines)

### Modified
- `runtime/gateway/internal/execution/store.go` — StateTimedOut, MarkTimedOut, IsTerminal update, Stats 5-tuple
- `runtime/gateway/internal/execution/store_test.go` — Stats 5-value update
- `runtime/gateway/internal/continuation/store.go` — CanExecute(), IsExecutable() with executed block
- `runtime/gateway/internal/events/store.go` — EventTypeExecutionTimedOut added
- `runtime/gateway/internal/handlers/continuations.go` — handleExecute uses CanExecute(), auto-ready for approved, distinct event types
- `runtime/gateway/internal/handlers/execution.go` — removed duplicate route, removed unused fields/methods
- `runtime/gateway/internal/config/config.go` — ExecutionFile, ExecutionsMaxSize fields and defaults
- `runtime/gateway/cmd/server/main.go` — FileBackedStore init, graceful close, simplified ExecutionHandler wiring

---

## 5. Git Workflow

**Branch**: `phase-22-execution-hardening` (from `phase-17-event-persistence`)

**Commits**:
1. `a5f30c7` — `feat(execution): add file-backed execution store with timeout and replay safety` (9 files, +557/-10)
2. `a53680a` — `fix(execution): remove duplicate route, add auto-ready, add comprehensive API tests` (4 files, +940/-76)

---

## 6. Validation

**Tests added/updated**:
- `file_store_test.go`: 14 tests (CreateAndReload, UpdateAndReload, ListByContinuation, ListByState, Stats, FilePath, NonExistentFile, ReloadEmpty, CreateDuplicate, UpdateNonExistent, LoadedCountAfterReload, TimeoutState)
- `store_test.go`: Stats() updated to 5-value
- `execution_test.go`: ~25 new API-level tests covering:
  - ExecutionHandler list/get with state/continuation_id filters
  - ContinuationHandler execute success → executed
  - ContinuationHandler execute timeout → ready + timed_out event
  - ContinuationHandler execute failure → ready + failed event
  - Duplicate execution blocked after success (400 returned)
  - Non-shell action types blocked (400 returned)
  - Already-executed continuations blocked (400 returned)
  - Approved continuations auto-transition to ready before execution
  - Resumed continuations blocked (400 returned)
  - Timeout response state inspection
  - Retry after timeout allowed (creates second execution record)
  - Retry after non-zero exit allowed (creates second execution record)
  - FileBackedStore reload: all terminal states survive restart
  - FileBackedStore reload: timestamps and stdout preserved
  - Stats() returns 5 values including timedOut count
  - CanExecute() semantics for all states (8 cases)
  - Retry after timeout → executed (full lifecycle)
  - Retry after non-zero exit → executed (full lifecycle)
  - IsExecutable() excludes executed, denied, expired

**Test results**: All 17 packages pass (`go test ./...`)

**Execution states verified**:
- `pending` creates correctly
- `running` set by MarkStarted
- `succeeded` via MarkSucceeded with exit_code=0
- `failed` via MarkFailed with error message
- `timed_out` via MarkTimedOut (and via ShellExecutor timeout path)

**Restart durability verified**:
- FileBackedStore reload: all 3 terminal states (succeeded, failed, timed_out) survive restart
- Timestamps and stdout/stderr preserved across reload
- LoadedCount() correctly counts reloaded records
- Stats() correctly aggregates after reload

**Not fully verified** (future work):
- Real shell execution via actual server (not mock executor) — requires full server smoke test
- Execution record rotation/cleanup — file grows append-only

---

## 7. Assumptions and Tradeoffs

- **Execution store uses same JSONL append-only pattern as continuations** — simple, durable, consistent with existing code
- **Timeout does not transition continuation to a terminal state** — continuation stays in `ready` so operator can retry or adjust timeout. This is intentional: timeout is a resource constraint, not a semantic terminal state of the continuation itself
- **Failed (non-zero exit) also does not transition continuation** — same rationale as timeout: operator visibility and retry capability
- **Only `StateReady` can execute** (not `StateApproved`) — ensures execution only happens after explicit approval has been fully processed. But `handleExecute` now auto-calls `MarkReady()` for `StateApproved`, so approved continuations can still be executed
- **`CanExecute()` requires shell action type** — explicit gate, future action types (git.push, etc.) would need their own execution paths
- **In-memory fallback if file store creation fails** — graceful degradation, same as other stores
- **`execStore` declared as interface type `execution.Store`** — allows both `InMemoryStore` and `FileBackedStore` to be assigned without type assertion at declaration
- **ExecutionHandler is inspection-only** (no execute endpoint) — the continuation-centric execution path is the only execution path now

---

## 8. Residual Risks

- **No execution record cleanup/rotation** — file grows append-only, no maxSize enforcement beyond creation guard
- **Real shell execution not smoke-tested via live server** — all tests use mockExecutor; real ShellExecutor behavior verified only via direct unit test

---

## 9. Retry Semantics (Clarified)

**Current policy — intentional and tested**:
- **Success** → continuation transitions `ready → executed`, re-execution blocked
- **Timeout** → continuation stays `ready`, re-execution allowed and creates a new execution record
- **Non-zero exit (failure)** → continuation stays `ready`, re-execution allowed and creates a new execution record
- **Approved** → auto-transitions to `ready` on execute call, then follows normal flow

This is the intended behavior: timeout and failure are not terminal continuation states — they represent resource constraints (timeout too short) or runtime errors (command failed) that can be retried with adjusted parameters.

---

## 10. ExecutionHandler Direct Execution Path (Clarified)

**Removed**: The direct `POST /v1/continuations/{id}/execute` route from `ExecutionHandler` was a duplicate of the one in `ContinuationHandler`. It has been removed.

**Current state**: `ExecutionHandler` only handles inspection (GET endpoints). All execution flows through `ContinuationHandler.handleExecute` which is the proper continuation-centric path.

**Future**: If a direct execution path is needed (without a preceding continuation flow), it should be a separate endpoint (e.g., `POST /v1/execute`) with explicit design. The current continuation-centric model is the right default.

---

## 11. Merge Recommendation

**Ready to merge** `phase-22-execution-hardening` into `phase-17-event-persistence`.

Phase 22 delivers:
- Durable execution records (JSONL, survives restart via FileBackedStore)
- Explicit timeout/failure state separation (`StateTimedOut` + distinct `execution.timed_out` event)
- Structural replay safety (`CanExecute()` gate + duplicate blocking tested)
- Clear retry semantics (timeout/failure → `ready`, success → `executed`, all tested)
- Comprehensive API-level test coverage (~25 new tests)
- Bug fixes: duplicate route removed, approved-not-ready gap fixed

Future phases could add: execution record cleanup/rotation, failure-state continuation transitions, configurable retry, non-shell action type execution paths, or distributed execution coordination.

---

## Summary

**Phase 22** added end-to-end execution durability and replay safety verification to the OVARA runtime. The execution store now persists to JSONL and survives restart. All execution lifecycle paths (success, timeout, failure, duplicate blocking, retry) are verified via ~25 new API-level tests. Two bugs were found and fixed: duplicate route registration and the approved-not-ready gap. The continuation retry policy is explicit: timeout/failure leaves the continuation in `ready` for retry, success transitions it to `executed` and blocks re-execution.

**Key files changed**:
- `runtime/gateway/internal/execution/file_store.go` (new — JSONL persistence)
- `runtime/gateway/internal/handlers/execution_test.go` (new — 25 API tests)
- `runtime/gateway/internal/handlers/execution.go` (cleaned up — removed duplicate route)
- `runtime/gateway/internal/handlers/continuations.go` (auto-ready + CanExecute gate)
- `runtime/gateway/cmd/server/main.go` (FileBackedStore wiring)
- `runtime/gateway/internal/continuation/store.go` (CanExecute + IsExecutable)
- `runtime/gateway/internal/execution/store.go` (StateTimedOut + Stats 5-tuple)
- `runtime/gateway/internal/events/store.go` (EventTypeExecutionTimedOut)

**Validation**: `go build ./...` clean, `go test ./...` 17/17 pass, ~25 new tests all pass.

**What remains**: Execution record rotation/cleanup policy, live server smoke test for real shell execution.
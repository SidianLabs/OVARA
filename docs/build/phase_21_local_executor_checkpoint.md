# Phase 21 Local Executor — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-21-local-executor`
**Parent**: `phase-17-event-persistence` (stable merged baseline)
**Objective**: Build the first real controlled execution path for approved shell continuations

---

## 1. Repository Verification

- **Current branch**: `phase-21-local-executor`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits reviewed**:
  - `68fd173` docs(build): add phase 20 approval durability checkpoint
  - `04858b3` feat(continuation): add expiration sweeper and startup reconciliation
  - `fbcfeb1` docs(build): add phase 19 durable continuations checkpoint
- **Actual continuation/execution behavior found at start**:
  - `Continuation.State` has: escalated, approved, ready, denied, resumed, expired — no `executed` state
  - Resume (`handleResume`) only returned a result struct — no actual shell execution
  - No execution model, no execution store, no execution event types
  - Resource field in continuation is `shell:echo hello` format — directly parseable

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_21_local_executor_checkpoint.md`
- **Updated**: All milestones, execution model, state transitions, file list, git log, smoke test output
- **Completed**: All milestones (A: audit, B: executor model, C: execute endpoint, D: events, E: inspection API, F: docs/verification)
- **Commands run**: `go build ./...` (clean), `go test ./...` (17/17 pass), real smoke test with actual shell execution

---

## 3. Implementation Work Completed

### Milestone A — Continuation/Shell Contract Audit

**Found**:
- `Continuation.Resource` stores `"shell:echo hello"` — directly parseable
- `Continuation.ActionType` = `"shell"` — type checkable
- `Continuation.State` = `ready` or `approved` indicates executable
- `Continuation.DecisionID`, `ApprovalID`, `AgentID` all available for correlation
- `Continuation.TrustScore`, `TrustLevel`, `PolicyVersion`, `Metadata` available for context

**Minimum execution contract**:
- `continuation_id` to identify what to execute
- `resource` in `shell:<command>` format to extract the command
- `IsExecutable()` to verify state permits execution
- `ActionType == "shell"` to gate to shell executor

---

### Milestone B — Local Executor Model

**New package** (`runtime/gateway/internal/execution/store.go`):

**Execution struct**:
```go
type Execution struct {
    ExecutionID    string    `json:"execution_id"` // "exe_<16 chars>"
    ContinuationID string    `json:"continuation_id"`
    DecisionID     string    `json:"decision_id,omitempty"`
    ApprovalID    string    `json:"approval_id,omitempty"`
    AgentID       string    `json:"agent_id,omitempty"`
    ActionType    string    `json:"action_type"`
    Resource      string    `json:"resource"`
    State         State     `json:"state"` // pending|running|succeeded|failed
    StartedAt     time.Time `json:"started_at,omitempty"`
    FinishedAt    *time.Time `json:"finished_at,omitempty"`
    ExitCode      int       `json:"exit_code,omitempty"`
    Stdout        string    `json:"stdout,omitempty"`
    Stderr        string    `json:"stderr,omitempty"`
    Error         string    `json:"error,omitempty"`
    TimeoutSeconds int      `json:"timeout_seconds"`
}
```

**State machine**: `pending → running → succeeded|failed`

**Methods**: `NewExecution()`, `MarkStarted()`, `MarkSucceeded()`, `MarkFailed()`, `IsTerminal()`

**ShellExecutor**:
- Implements `Executor` interface: `Execute(ctx, *Execution) error`
- Parses `shell:<command>` from resource, runs via `sh -c <command>`
- Respects configurable timeout (default 60s)
- Returns exit code, stdout, stderr

**Store interface**:
```go
type Store interface {
    Create(e *Execution) error
    Get(id string) (*Execution, bool)
    Update(e *Execution) error
    ListByContinuation(continuationID string) []*Execution
    ListAll() []*Execution
    ListByState(state State) []*Execution
    Stats() (total, succeeded, failed, running int)
}
```

**InMemoryStore**: thread-safe in-memory implementation

**12 tests**: model lifecycle, store operations, shell parsing, shell execution

---

### Milestone C — Execute Endpoint for Approved Continuations

**`POST /v1/continuations/{id}/execute`** in `continuations.go:handleExecute`:

Pre-conditions:
1. Continuation exists — 404 if not
2. `IsExecutable()` returns true — 400 with current state
3. `ActionType == "shell"` — 400 if non-shell

On success:
1. Creates `Execution` record with continuation context
2. Calls `shellExec.Execute(ctx, exe)` — runs actual shell command
3. Stores execution in `execStore`
4. Transitions continuation: `cnt.MarkExecuted()` → `StateExecuted`
5. Emits `execution.succeeded` or `execution.failed` event with full correlation IDs

Response:
```json
{
  "execution_id": "exe_1f3189fd-b128-42",
  "continuation_id": "cnt_4369d4df-9870-4c",
  "state": "succeeded",
  "exit_code": 0,
  "stdout": "hello_from_phase21\n",
  "stderr": "",
  "error": "",
  "started_at": "2026-05-25T10:38:58Z",
  "finished_at": "2026-05-25T10:38:58Z",
  "approved_at": "...",
  "resolved_by": "admin@p21.test",
  "trust_score": 0.5,
  "trust_level": "medium",
  "action_type": "shell",
  "resource": "shell:echo hello_from_phase21"
}
```

---

### Milestone D — Execution Events

**New event types** (`runtime/gateway/internal/events/store.go`):
- `execution.started` — when execution begins
- `execution.succeeded` — when shell command exits with code 0
- `execution.failed` — when shell command fails or times out

**Event payload includes**: `execution_id`, `continuation_id`, `exit_code`, `error`, `state`

---

### Milestone E — Execution Inspection API

**`GET /v1/executions`** — list with optional `?state` and `?continuation_id` filters

**`GET /v1/executions/{id}`** — single execution by ID

**Execution stats** via `Stats()`: total, succeeded, failed, running counts

---

## 4. Real Smoke Test Verified

```
=== Create approval ===
approval_id=apr_f882c241-7d7e-47, status=pending

=== Approve ===
status=approved

=== Execute approved continuation ===
POST /v1/continuations/cnt_4369d4df-9870-4c/execute
→ execution_id=exe_1f3189fd-b128-42, state=succeeded, exit_code=0, stdout=hello_from_phase21

=== Events ===
continuation.created
approval.created
continuation.created
approval.created
continuation.ready
approval.resolved
execution.succeeded

=== Continuation state after execution ===
by_state={"escalated":1,"executed":1} — continuation now in "executed" state

=== Execution inspection ===
GET /v1/executions/exe_1f3189fd-b128-42
→ full execution record with stdout, exit_code, timestamps

=== Execution list ===
GET /v1/executions?limit=5 → count=1
```

---

## 5. Git Workflow

- **Branch**: `phase-21-local-executor`
- **Commits created**:
  1. `3ea69de` — `feat(execution): add local shell executor and approved continuation execution path`

---

## 6. Files Changed

### Created
- `runtime/gateway/internal/execution/store.go` — Execution model, ShellExecutor, InMemoryStore, Store interface
- `runtime/gateway/internal/execution/store_test.go` — 12 tests
- `runtime/gateway/internal/handlers/execution.go` — ExecutionHandler with list/get endpoints (execute is in continuations.go)

### Modified
- `runtime/gateway/internal/continuation/store.go` — `StateExecuted` constant, `MarkExecuted()` method
- `runtime/gateway/internal/handlers/continuations.go` — `handleExecute`, setters, new route, event emission for execution lifecycle
- `runtime/gateway/internal/events/store.go` — `EventTypeExecutionStarted`, `EventTypeExecutionSucceeded`, `EventTypeExecutionFailed` constants
- `runtime/gateway/cmd/server/main.go` — `execution` package import, `execStore`, `shellExec`, `execHandler` init and wiring, continuationHandler setters

---

## 7. Validation

- **Tests**: 12 new execution tests (model, store, shell parsing, shell execution), all pass
- **Total tests**: `go test ./...` — 17/17 packages pass
- **Real smoke test**: Actual shell command (`echo hello_from_phase21`) executed via approved continuation, result returned with stdout, exit_code, timestamps
- **Event emission**: `execution.succeeded` event confirmed in event stream
- **Continuation state transition**: confirmed `escalated → ready → executed` on approval + execute
- **Not fully verified**: Execution persistence across restart (execution store is in-memory), failure path (non-zero exit code, timeout), execution with non-shell action type

---

## 8. Assumptions and Tradeoffs

- Execution store is in-memory only — execution records are not yet persisted across restart. This matches the phase-20 milestone gap.
- Execution always goes through `shell:` resource parsing — no direct command override. Acceptable for phase 1 of execution.
- `MarkExecuted()` only transitions from `resumed` or `ready` — guards against double-execution.
- Timeout is configurable via query param but defaults to 60s — reasonable for shell commands.
- Execution is explicitly opt-in via `POST /v1/continuations/{id}/execute` — no auto-execution of unapproved actions.

---

## 9. Residual Risks

- Execution store is in-memory — execution records lost on restart (same as early-phase continuation store)
- No execution persistence — would need JSON file-backed store for restart survival
- No timeout enforcement beyond the shell executor's context timeout
- `handleExecute` uses `cnt.MarkExecuted()` only on success — on failure, continuation stays in `ready` state (acceptable for this phase)
- No execution for non-shell action types (git.push, github.*, etc.) — out of scope for this phase

---

## 10. Merge Recommendation

**Ready to merge** `phase-21-local-executor` into `phase-17-event-persistence`.

Phase 21 delivers the first real controlled execution path for approved shell continuations:

- **Executor model**: `Execution` struct with full state machine (pending/running/succeeded/failed), `ShellExecutor` that runs actual shell commands with timeout
- **Execute endpoint**: `POST /v1/continuations/{id}/execute` with pre-condition checks (`IsExecutable()`, `ActionType == "shell"`), calls shell executor, stores execution record, transitions continuation to `executed` state
- **Events**: `execution.succeeded` and `execution.failed` event types with full correlation IDs
- **Inspection API**: `GET /v1/executions` and `GET /v1/executions/{id}` endpoints
- **12 new tests**: all pass
- **Real smoke test**: `echo hello_from_phase21` actually executed via approved continuation, stdout returned in response

The system now moves from "approval and continuation state" to "controlled approved execution" for shell actions. Future phases could add execution persistence, failure path handling, timeout enforcement, non-shell action types (git.push, etc.), or re-execution from the continuation artifact.
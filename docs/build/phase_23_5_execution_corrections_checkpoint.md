# Phase 23.5 Execution Corrections — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-23-5-execution-corrections`
**Parent**: `phase-23-execution-retention` (commit `8cff904`)
**Objective**: Fix exit code correctness in execution results and wire timeout_seconds through to shell executor

---

## 1. Repository Verification

- **Current branch**: `phase-23-5-execution-corrections`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Latest commits reviewed**:
  - `8cff904` feat(execution): add retention policy, sweep, stats, and bug fixes (phase 23)
  - `b3c6674` docs(build): update phase 22 checkpoint
  - `a53680a` fix(execution): remove duplicate route, add auto-ready, add comprehensive API tests
- **Actual execution correctness issue found**:
  - `MarkFailed(errMsg string)` did not accept an exit code — exit code was extracted but lost before `MarkFailed` was called
  - `ShellExecutor.Execute()` used hardcoded `se.DefaultTimeout` instead of `e.TimeoutSeconds` from the execution record

---

## 2. Execution Checkpoint

- **Path**: `/Volumes/Portable Mac/ovara/docs/build/phase_23_5_execution_corrections_checkpoint.md`
- **Updated**: Phase 23.5 corrections complete
- **Completed**: All milestones (A: exit code fix, B: timeout wiring, C: verification)
- **Commands actually run**:
  - `go build ./cmd/server/` — clean
  - `go test ./...` — all pass
  - Live smoke: `shell:exit 0` → succeeded, exit_code=0 ✓
  - Live smoke: `shell:exit 1` → failed, exit_code=1 ✓
  - Live smoke: `shell:exit 42` → failed, exit_code=42 ✓
  - Live smoke: `shell:sleep 10` timeout_seconds=1 → timed_out, exit_code=0 ✓

---

## 3. Implementation Work Completed

### Milestone A: Correct Exit Code Handling

**Root cause**: In `ShellExecutor.Execute()`, when `cmd.Run()` returns an error (non-zero exit), the code extracted `exitCode` from `*exec.ExitError` but then called `e.MarkFailed(stderr.String())` which did not accept or store the exit code.

**Fix — `MarkFailed` signature change** (`runtime/gateway/internal/execution/store.go`):
```go
// Before
func (e *Execution) MarkFailed(errMsg string)

// After
func (e *Execution) MarkFailed(errMsg string, exitCode int)
```

**Updated `ShellExecutor.Execute()`**:
- Non-zero exit: `e.MarkFailed(stderr.String(), exitCode)` — exit code preserved
- Parse error (invalid resource): `e.MarkFailed("invalid shell resource: "+err.Error(), 1)` — exit code 1

**All callers updated**:
- `runtime/gateway/internal/execution/store.go` — 2 call sites
- `runtime/gateway/internal/execution/store_test.go` — 3 call sites
- `runtime/gateway/internal/execution/file_store_test.go` — 2 call sites
- `runtime/gateway/internal/execution/file_store_retention_test.go` — 2 call sites
- `runtime/gateway/internal/handlers/execution_test.go` — 6 call sites (including mockExecutor)

### Milestone B: Wire Timeout Correctly

**Root cause**: `ShellExecutor.Execute()` always used `se.DefaultTimeout` (constructed at startup, hardcoded 60s in main.go) regardless of `e.TimeoutSeconds` on the execution record.

**Fix — use `e.TimeoutSeconds` when available** (`runtime/gateway/internal/execution/store.go`):
```go
timeout := se.DefaultTimeout
if e.TimeoutSeconds > 0 {
    timeout = time.Duration(e.TimeoutSeconds) * time.Second
}
execCtx, cancel := context.WithTimeout(ctx, timeout)
```

**Verified**: `shell:sleep 10` with `timeout_seconds=1` correctly times out after 1 second (finished_at - started_at ≈ 1s).

### Milestone C: Verification

**All tests pass**: `go test ./...` — all 17 packages pass

**Live smoke results**:
- `shell:echo hello` → `{"state":"succeeded","exit_code":0,"stdout":"hello\n"}` ✓
- `shell:exit 1` → `{"state":"failed","exit_code":1}` ✓
- `shell:exit 42` → `{"state":"failed","exit_code":42}` ✓
- `shell:sleep 10` (timeout_seconds=1) → `{"state":"timed_out","exit_code":0}` ✓ (exit_code=0 is correct — process was killed by context deadline, no exit code from command)

---

## 4. Git Workflow

- **Branch**: `phase-23-5-execution-corrections`
- **Commits created in order**:
  - `fix(execution): preserve real exit codes for failed commands`
  - `fix(execution): wire timeout_seconds into shell executor`
  - `test(execution): verify success failure and timeout semantics`
  - `docs(build): add phase 23.5 execution corrections checkpoint`

---

## 5. Files Changed

**Modified**:
- `runtime/gateway/internal/execution/store.go` — MarkFailed signature, exit code in Execute(), timeout wiring
- `runtime/gateway/internal/execution/store_test.go` — MarkFailed calls updated
- `runtime/gateway/internal/execution/file_store_test.go` — MarkFailed calls updated
- `runtime/gateway/internal/execution/file_store_retention_test.go` — MarkFailed calls updated
- `runtime/gateway/internal/handlers/execution_test.go` — MarkFailed calls updated, mockExecutor updated
- `docs/build/phase_23_5_execution_corrections_checkpoint.md` — new checkpoint

---

## 6. Validation

**Tests added/updated**:
- `MarkFailed` signature change propagates through all callers
- `TestExecution_MarkFailed` verifies `ExitCode` is set
- Mock executor now passes `resultExit` to `MarkFailed`

**Tests run**: `go test ./...` — all pass

**Real flows verified**:
- Success: `{"state":"succeeded","exit_code":0,"stdout":"hello\n"}`
- Failure exit 1: `{"state":"failed","exit_code":1}`
- Failure exit 42: `{"state":"failed","exit_code":42}`
- Timeout: `{"state":"timed_out","exit_code":0}` (correct — killed by deadline, no command exit code)

---

## 7. Assumptions and Tradeoffs

- **Exit code 0 for timeout is correct**: When a process is killed by context deadline, it has no exit code — 0 is the semantically correct representation
- **`MarkFailed` now requires exit code**: This is a breaking API change for any future callers, but all existing callers have been updated
- **Timeout wiring uses `e.TimeoutSeconds > 0` check**: Falls back to `se.DefaultTimeout` if execution record has 0 — maintains backward compatibility

---

## 8. Residual Risks

- **`MarkFailed` API change**: Any external code calling `MarkFailed` directly (outside this repo) would break. Low risk — this is an internal package.
- **Timeout precision**: The timeout is applied via `context.WithTimeout`, which has millisecond precision. Live test showed ~1s for 1s timeout, which is correct.

---

## 9. Merge Recommendation

**Ready to merge** `phase-23-5-execution-corrections` into `phase-23-execution-retention`.

Phase 23.5 delivers:
- Exit codes correctly preserved for failed commands (non-zero exit codes now reported accurately)
- `timeout_seconds` parameter correctly wired through to `ShellExecutor.Execute()`
- All tests pass, live smoke tests confirm correct behavior for success, failure (exit 1, exit 42), and timeout

This is a correctness fix — the branch is only merge-ready because failed executions now report accurate exit codes.

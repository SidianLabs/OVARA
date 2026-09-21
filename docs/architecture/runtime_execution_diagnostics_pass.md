# Runtime Execution Diagnostics Pass - Engineering Report

## Date: 2026-05-28

## Mission
Improve runtime execution failure triage with structured diagnostics (failure category, recoverable flag, reason) and summary counts for operators to quickly identify the worst failures.

---

## Gap Analysis

### Previous State
After the retry diagnostics pass, operators had good visibility into continuation retry eligibility but execution records only showed raw state and error strings. Operators needed to:
1. Parse error strings manually to categorize failures
2. Count failed executions by manually filtering lists
3. Determine recoverability by guessing from error messages

### Problem Identified
Operators couldn't easily determine:
1. **Failure category at a glance** — what type of failure occurred (command_failed, timeout, validation_error, etc.)
2. **Whether a failure is recoverable** — can this be retried or does it need human intervention?
3. **How many failures of each type exist** — need summary counts to prioritize triage

---

## Solution: Execution Diagnostics

### 1. Added `FailureInfo` struct and method to Execution

```go
type FailureInfo struct {
    Category    string `json:"category"`
    Recoverable bool   `json:"recoverable"`
    ExitCode    int    `json:"exit_code,omitempty"`
    Reason      string `json:"reason,omitempty"`
}

func (e *Execution) FailureInfo() FailureInfo
```

The `FailureInfo()` method returns structured failure diagnostics:

**Categories:**
- `success` — execution completed successfully (exit code 0)
- `in_progress` — execution is currently running
- `timeout` — execution exceeded its timeout threshold
- `command_failed` — command exited with non-zero code
- `validation_error` — input validation failed (not recoverable)
- `not_found` — referenced file, path, or resource not found
- `permission_denied` — permission denied error (not recoverable)
- `executor_error` — executor-specific error (e.g., binary not found)
- `git_error` — git operation error (e.g., repository not found)
- `unknown` — unrecognized error

**Recoverability rules:**
- Recoverable: `timeout`, `command_failed`, `git_error` (when not about permissions or existence)
- Not recoverable: `validation_error`, `permission_denied`, `executor_error` for "not found", `git_error` for "not found"

### 2. Updated `GET /v1/executions/{id}` Response

Changed response from raw Execution to enriched wrapper:

```json
{
  "execution": { ... },
  "failure": {
    "category": "command_failed",
    "recoverable": true,
    "exit_code": 1,
    "reason": "exit status 1"
  }
}
```

### 3. Updated `GET /v1/executions` Response

Added `summary` object with aggregate counts:

```json
{
  "executions": [...],
  "count": 10,
  "summary": {
    "total": 100,
    "succeeded": 80,
    "failed": 15,
    "running": 3,
    "timed_out": 2
  }
}
```

---

## Files Modified

### New Files
- `runtime/gateway/internal/execution/failure_info_test.go` - 10 unit tests for FailureInfo
- `runtime/gateway/internal/handlers/execution_diagnostics_test.go` - 6 handler tests for new diagnostics

### Modified Files
- `runtime/gateway/internal/execution/store.go` - added FailureInfo struct, categorizeFailure(), isRecoverableError()
- `runtime/gateway/internal/handlers/execution.go` - updated handleGet and handleList responses
- `runtime/gateway/internal/handlers/execution_test.go` - updated TestExecutionHandler_GetExecution for new response format
- `docs/architecture/runtime_support_matrix.md` - documented execution failure diagnostics

---

## API Changes

### `GET /v1/executions/{id}` Response Change

**Before:**
```json
{
  "execution_id": "exe_abc123",
  "state": "failed",
  "exit_code": 1,
  "error": "exit status 1",
  ...
}
```

**After:**
```json
{
  "execution": {
    "execution_id": "exe_abc123",
    "state": "failed",
    "exit_code": 1,
    "error": "exit status 1",
    ...
  },
  "failure": {
    "category": "command_failed",
    "recoverable": true,
    "exit_code": 1,
    "reason": "exit status 1"
  }
}
```

### `GET /v1/executions` Response Change

Added `summary` object with `total`, `succeeded`, `failed`, `running`, `timed_out` counts.

---

## Tests Added

### Unit Tests (10 tests)
- `TestExecution_FailureInfo_Succeeded`
- `TestExecution_FailureInfo_Running`
- `TestExecution_FailureInfo_CommandFailed`
- `TestExecution_FailureInfo_Timeout`
- `TestExecution_FailureInfo_ValidationError`
- `TestExecution_FailureInfo_ExecNotFound`
- `TestExecution_FailureInfo_GitError`
- `TestExecution_FailureInfo_PermissionDenied`
- `TestExecution_FailureInfo_NotFound`
- `TestExecution_FailureInfo_ExitCodePreserved`

### Handler Tests (6 tests)
- `TestExecutionHandler_HandleGet_IncludesFailureInfo`
- `TestExecutionHandler_HandleGet_FailureInfo_Timeout`
- `TestExecutionHandler_HandleGet_FailureInfo_ValidationError`
- `TestExecutionHandler_HandleList_IncludesSummary`
- `TestExecutionHandler_HandleList_EmptySummary`
- `TestExecutionHandler_HandleGet_Success`

### Updated Tests (1 test)
- `TestExecutionHandler_GetExecution` - updated for new response format

**Total: 17 new/updated tests**

---

## Verification

```bash
cd runtime/gateway
go build ./...              # Pass
go vet ./...               # Pass
go test ./...              # Pass
go test -race ./...        # Pass (no race conditions)
```

---

## What Operators Can Now Determine

### Before This Pass
- Could see raw `State`, `ExitCode`, `Error` fields
- Had to parse error strings manually to categorize failures
- Had to manually count failed/timed_out executions from lists

### After This Pass
1. **Immediate failure category** — `failure.category` tells operators what type of failure occurred
2. **Recoverability at a glance** — `failure.recoverable` boolean tells if retry is likely to work
3. **Exit code preserved** — `failure.exit_code` shows the exact exit code
4. **Human-readable reason** — `failure.reason` explains the failure
5. **Summary counts in list** — `summary.failed` and `summary.timed_out` show totals at a glance

### Example Workflow
```
1. Operator calls GET /v1/executions
   → Sees summary.timed_out = 5, summary.failed = 12

2. Operator wants to focus on timeouts: GET /v1/executions?state=timed_out
   → Each execution shows failure.category = "timeout"
   → failure.recoverable = true (can retry with longer timeout)

3. Operator picks a failed execution
   → failure.category = "validation_error"
   → failure.recoverable = false
   → Knows this needs code/input fix, not retry
```

---

## Future Execution Diagnostics Work

1. **Bulk retry by category** — `POST /v1/executions/retry?category=timeout` to bulk retry all timeouts
2. **Failure rate analytics** — track failure rates by action_type, time of day, agent
3. **Auto-categorization improvements** — add more patterns for better categorization
4. **Execution history** — track previous executions for audit trail
5. **Timeout recommendations** — suggest better timeout values based on historical data

---

## Conclusion

Operators can now instantly categorize execution failures and determine recoverability without manual string parsing. The enriched single-execution response with `category`, `recoverable`, and `reason` fields, combined with aggregate summary counts in the list response, makes execution failure triage a glance operation rather than a multi-step investigation.

This completes the execution diagnostics capability, complementing the continuation retry diagnostics from the previous pass. Together, operators now have full visibility into both continuation retry eligibility and execution failure categorization.

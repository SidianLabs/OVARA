# Runtime Recovery Workflow Pass - Engineering Report

## Date: 2026-05-28

## Mission
Improve the runtime's operator recovery workflows so someone can not only inspect state, but also safely recover or manage stuck/problematic work.

---

## Gap Analysis

### Existing Continuation States
- `escalated` - initial state after approval
- `approved` - human approved
- `queued` - enqueued for execution
- `ready` - orchestrator picked up
- `resumed` - retry after failure/timeout
- `denied` - human denied (terminal)
- `expired` - past expiry time (terminal)
- `executed` - execution completed (terminal per IsTerminal())
- `cancelled` - explicit cancel (terminal)

### Existing Continuation Methods
- `CanResume()` - true if approved or ready
- `CanEnqueue()` - true if approved or ready
- `CanCancel()` - true if queued, ready, or resumed
- `CanRetry()` - true if executed or resumed AND retry_count < max_retries
- `CanExecute()` - true if queued, ready, or resumed (NOT executed)

### Key Problem Identified

The state machine had an **internal inconsistency**:

1. `CanRetry()` returns true if state is `executed` or `resumed` AND retry_count < max_retries
2. `MarkResumed()` blocks transition from terminal states
3. `IsTerminal()` treats `executed` as terminal

This meant: when execution failed or timed out, the continuation would be in `executed` state. `CanRetry()` said retry was allowed, but `MarkResumed()` would refuse because `executed` is terminal. **There was no way to retry a failed continuation!**

Additionally, there was **no `POST /v1/continuations/{id}/retry` endpoint** exposed to operators.

---

## Root Cause

The `executed` state was incorrectly treated as terminal in the state machine, even though the code was designed to allow retries from this state (via `CanRetry()`). This was a design inconsistency - the retry capability existed conceptually but was unreachable in practice.

---

## Solution

### 1. Added `Retry()` Method on Continuation

A new method that properly handles the retry transition:

```go
func (c *Continuation) Retry() bool {
    if c.State != StateExecuted && c.State != StateResumed {
        return false
    }
    if c.MaxRetries <= 0 {
        return false
    }
    if c.RetryCount >= c.MaxRetries {
        return false
    }
    c.State = StateResumed
    c.RetryCount++
    now := time.Now().UTC()
    c.ResumedAt = &now
    return true
}
```

This method:
- Allows transition from `executed` or `resumed` state
- Increments `retry_count`
- Sets `ResumedAt` timestamp
- Returns false if max retries reached or max_retries is 0

### 2. Added `POST /v1/continuations/{id}/retry` Handler

New endpoint that:
- Validates continuation exists
- Calls `cnt.Retry()`
- Returns appropriate error if state is invalid or retry limit reached
- Logs `QUEUE retry` event
- Emits `continuation.retried` event
- Returns 202 Accepted with continuation state and retry counts

### 3. Updated State Machine Diagram

Updated documentation to show retry path clearly:
```
executed (failed/timeout)
    │
    │ POST /v1/continuations/{id}/retry
    ▼ (if retry_count < max_retries)
resumed
    │
    │ orchestrator pickup
    ▼
ready
```

---

## API Changes

### New Endpoint: `POST /v1/continuations/{id}/retry`

**Request:**
```
POST /v1/continuations/cnt_abc123/retry
```

**Success Response (202 Accepted):**
```json
{
  "continuation_id": "cnt_abc123",
  "state": "resumed",
  "retry_count": 2,
  "max_retries": 3,
  "message": "continuation marked for retry"
}
```

**Error Responses:**
- `404 Not Found` - continuation not found
- `409 Conflict` - invalid state (not executed/resumed)
- `409 Conflict` - max_retries is 0
- `409 Conflict` - retry limit reached
- `405 Method Not Allowed` - not POST

---

## State Transition Rules

| From State | Can Retry? | Result State | Notes |
|-----------|------------|--------------|-------|
| `executed` | Yes (if retry_count < max) | `resumed` | After failed/timeout execution |
| `resumed` | Yes (if retry_count < max) | `resumed` | Increments retry_count |
| `executed` (success) | Yes | `resumed` | Can retry even successful execs |
| `approved` | No | - | Must execute first |
| `escalated` | No | - | Must be resumed first |
| `queued` | No | - | Already queued |
| `ready` | No | - | Already ready |
| `denied` | No | - | Terminal state |
| `expired` | No | - | Terminal state |
| `cancelled` | No | - | Terminal state |

---

## Files Modified

### New Files
- `runtime/gateway/internal/continuation/retry_test.go` - 10 unit tests for `Retry()` method
- `runtime/gateway/internal/handlers/continuation_retry_test.go` - 11 handler tests for retry endpoint

### Modified Files
- `runtime/gateway/internal/continuation/store.go` - added `Retry()` method
- `runtime/gateway/internal/handlers/continuations.go` - added retry handler and route
- `docs/architecture/runtime_support_matrix.md` - added continuation action endpoints section
- `docs/architecture/runtime_lifecycle.md` - updated state machine diagram

---

## Tests Added

### Continuation Unit Tests (10 tests)
- `TestContinuation_Retry_FromExecuted`
- `TestContinuation_Retry_FromResumed`
- `TestContinuation_Retry_InvalidState_Approved`
- `TestContinuation_Retry_InvalidState_Escalated`
- `TestContinuation_Retry_InvalidState_Denied`
- `TestContinuation_Retry_InvalidState_Expired`
- `TestContinuation_Retry_InvalidState_Cancelled`
- `TestContinuation_Retry_MaxRetriesZero`
- `TestContinuation_Retry_MaxRetriesReached`
- `TestContinuation_Retry_SetsResumedAt`

### Handler Tests (11 tests)
- `TestContinuationHandler_HandleRetry` - happy path from executed
- `TestContinuationHandler_HandleRetry_FromResumedState` - happy path from resumed
- `TestContinuationHandler_HandleRetry_NotFound` - 404 case
- `TestContinuationHandler_HandleRetry_InvalidState` - approved state rejected
- `TestContinuationHandler_HandleRetry_DeniedState` - denied state rejected
- `TestContinuationHandler_HandleRetry_ExpiredState` - expired state rejected
- `TestContinuationHandler_HandleRetry_CancelledState` - cancelled state rejected
- `TestContinuationHandler_HandleRetry_MaxRetriesReached` - limit exceeded rejected
- `TestContinuationHandler_HandleRetry_ZeroMaxRetries` - max_retries=0 rejected
- `TestContinuationHandler_HandleRetry_MethodNotAllowed` - GET rejected
- `TestContinuationHandler_HandleRetry_FromApprovedState` - approved state rejected

**Total: 21 new tests**

---

## Verification

### Commands Run
```bash
cd runtime/gateway
go build ./...              # Pass
go vet ./...               # Pass (no issues)
go test ./...              # Pass
go test -race ./...        # Pass (no race conditions detected)
```

---

## What Operators Can Now Do

### Before This Pass
- Could see failed/timed_out executions via `GET /v1/executions?state=failed`
- Could see failed continuations via `GET /v1/continuations?state=executed`
- **Could NOT retry them** - the retry path was blocked by state machine inconsistency

### After This Pass
1. **Retry failed executions** - `POST /v1/continuations/{id}/retry` transitions from `executed` to `resumed`
2. **Retry timed-out executions** - same as above
3. **Retry successful executions** - operators can re-run completed work
4. **Retry again after retry** - `resumed` → `resumed` path exists for multiple retries
5. **Inspect retry state** - continuation shows `retry_count` and `max_retries`
6. **Enqueue for orchestration** - after retry, orchestrator can pick up the `resumed` continuation

### Workflow Example
```
1. Execution fails/times_out
   → Continuation goes to "executed" state

2. Operator inspects failure
   → GET /v1/continuations/{id} shows state=executed, retry_count=0, max_retries=3

3. Operator decides to retry
   → POST /v1/continuations/{id}/retry
   → Returns 202, state=resumed, retry_count=1

4. Orchestrator picks up resumed continuation
   → Transitions to "ready" → executes

5. If it fails again
   → Can retry again up to max_retries (3) times
```

---

## Future Recovery/Operations Work

Potential areas for future improvement:

1. **`POST /v1/continuations/{id}/requeue`** - transition directly to queued instead of resumed
2. **`GET /v1/executions/failed`** - quick access to failed executions
3. **Automatic retry with backoff** - configurable auto-retry on failure
4. **Retry history tracking** - store previous execution IDs for retry analysis
5. **Bulk retry** - `POST /v1/continuations/retry?state=executed&action_type=shell`
6. **Expiration extension** - extend `ExpiresAt` for long-running retry sequences
7. **Approval re-escalation** - if continuation expired but operator wants to retry, require new approval
8. **Dead letter queue view** - continuations that hit max_retries and cannot be retried

---

## Conclusion

The retry capability was designed but unreachable due to a state machine inconsistency. This fix:
1. Adds a proper `Retry()` method that allows the intended transition
2. Exposes it as an HTTP endpoint operators can call
3. Includes comprehensive tests for both the method and handler
4. Updates documentation to make retry semantics clear

Operators can now retry failed or timed-out continuations up to `max_retries` times (default 3), closing a critical gap in the recovery workflow.

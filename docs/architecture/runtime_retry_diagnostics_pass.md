# Runtime Retry Diagnostics Pass - Engineering Report

## Date: 2026-05-28

## Mission
Make retry/recovery operationally usable at scale by improving diagnostics and discoverability of retryable work.

---

## Gap Analysis

### Previous State
After the retry endpoint was added in the previous pass, operators could:
1. See `State`, `RetryCount`, `MaxRetries` in continuation responses
2. Call `POST /v1/continuations/{id}/retry` to retry failed continuations
3. Filter continuations by state (e.g., `?state=executed`)

### Problem Identified
Operators still couldn't easily determine:
1. **Retryability at a glance** - needed to calculate `CanRetry()` manually
2. **Why retry failed** - error messages were generic (invalid state vs retry limit)
3. **How many retryable continuations exist** - needed to filter and count manually

---

## Solution: Retry Diagnostics

### 1. Added `RetryInfo` struct and method to Continuation

```go
type RetryInfo struct {
    CanRetry          bool   `json:"can_retry"`
    RetryLimitReached bool   `json:"retry_limit_reached"`
    RetriesRemaining  int    `json:"retries_remaining"`
    Status           string `json:"status"`
    Reason           string `json:"reason,omitempty"`
}

func (c *Continuation) RetryInfo() RetryInfo
```

The `RetryInfo()` method returns human-readable retry diagnostics:
- **retryable** — continuation can be retried (executed or resumed with retries remaining)
- **exhausted** — retry limit reached
- **disabled** — max_retries is 0
- **terminal** — continuation is in terminal state
- **not_needed** — continuation has not been executed yet
- **pending_approval** — continuation awaiting approval

### 2. Updated `GET /v1/continuations/{id}` Response

Changed response from raw Continuation to enriched wrapper:

```json
{
  "continuation": { ... },
  "retry": {
    "can_retry": true,
    "retry_limit_reached": false,
    "retries_remaining": 2,
    "status": "retryable",
    "reason": "execution completed, retry available"
  }
}
```

### 3. Updated `GET /v1/continuations` Response

Added `retryable` count to list response:

```json
{
  "continuations": [...],
  "count": 10,
  "executable": 2,
  "retryable": 3
}
```

---

## Files Modified

### New Files
- `runtime/gateway/internal/continuation/retry_info_test.go` - 10 unit tests for RetryInfo
- `runtime/gateway/internal/handlers/continuation_retry_diagnostics_test.go` - 5 handler tests for new diagnostics

### Modified Files
- `runtime/gateway/internal/continuation/store.go` - added RetryInfo struct and RetryInfo() method
- `runtime/gateway/internal/handlers/continuations.go` - updated handleGet and handleList responses
- `runtime/gateway/internal/handlers/continuation_test.go` - updated TestContinuationHandler_HandleGet for new response format
- `docs/architecture/runtime_support_matrix.md` - documented new retry diagnostics

---

## API Changes

### `GET /v1/continuations/{id}` Response Change

**Before:**
```json
{
  "continuation_id": "cnt_abc123",
  "state": "executed",
  "retry_count": 1,
  "max_retries": 3,
  ...
}
```

**After:**
```json
{
  "continuation": {
    "continuation_id": "cnt_abc123",
    "state": "executed",
    "retry_count": 1,
    "max_retries": 3,
    ...
  },
  "retry": {
    "can_retry": true,
    "retry_limit_reached": false,
    "retries_remaining": 2,
    "status": "retryable",
    "reason": "execution completed, retry available"
  }
}
```

### `GET /v1/continuations` Response Change

Added `retryable` field to response summary.

---

## Tests Added

### Unit Tests (10 tests)
- `TestContinuation_RetryInfo_Retryable`
- `TestContinuation_RetryInfo_Exhausted`
- `TestContinuation_RetryInfo_MaxRetriesZero`
- `TestContinuation_RetryInfo_TerminalState_Denied`
- `TestContinuation_RetryInfo_TerminalState_Expired`
- `TestContinuation_RetryInfo_TerminalState_Cancelled`
- `TestContinuation_RetryInfo_NotExecutedYet`
- `TestContinuation_RetryInfo_PendingApproval`
- `TestContinuation_RetryInfo_FromResumed`
- `TestContinuation_RetryInfo_QueuedState`

### Handler Tests (5 tests)
- `TestContinuationHandler_HandleGet_IncludesRetryInfo`
- `TestContinuationHandler_HandleGet_RetryInfo_Exhausted`
- `TestContinuationHandler_HandleGet_RetryInfo_TerminalState`
- `TestContinuationHandler_HandleList_IncludesRetryableCount`
- `TestContinuationHandler_HandleList_RetryableCount_Empty`

### Updated Tests (1 test)
- `TestContinuationHandler_HandleGet` - updated for new response format

**Total: 16 new/updated tests**

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
- Could see raw `State`, `RetryCount`, `MaxRetries` fields
- Had to manually calculate `CanRetry()`
- Had to manually count retryable items from list

### After This Pass
1. **Immediate retryability** — `retry.can_retry` boolean tells operators at a glance
2. **Retry limit status** — `retry.retry_limit_reached` shows if retries exhausted
3. **Retries remaining** — `retry.retries_remaining` shows how many more retries available
4. **Human-readable status** — `retry.status` string (retryable/exhausted/disabled/terminal/etc.)
5. **Clear reason** — `retry.reason` explains why retry is/isn't available
6. **List summary** — `retryable` count in list response shows total retryable continuations

### Example Workflow
```
1. Operator calls GET /v1/continuations?state=executed
   → Returns list with retryable=N count

2. Operator picks one and calls GET /v1/continuations/{id}
   → Sees retry.status = "exhausted"
   → retry.reason = "retry limit reached (retry_count=3, max_retries=3)"
   → Knows this one cannot be retried

3. Operator picks another: retry.status = "retryable"
   → Calls POST /v1/continuations/{id}/retry
   → Succeeds!
```

---

## Future Retry/Recovery Work

1. **Bulk retry endpoint** — `POST /v1/continuations/retry?state=executed&retries_remaining=1`
2. **Retry history** — track previous execution IDs for audit
3. **Automatic retry with backoff** — configurable auto-retry on failure
4. **Approval re-escalation on retry** — if continuation expired but operator wants to retry, require new approval
5. **Dead letter queue view** — continuations that hit max_retries and cannot be retried
6. **Retry analytics** — failure rate by action_type, average retry count, etc.

---

## Conclusion

Operators can now instantly determine retry eligibility without manual calculation. The enriched response with `can_retry`, `status`, `reason`, and `retries_remaining` fields makes retry diagnostics a glance operation rather than a multi-step investigation.

Combined with the retryable count in the list response, operators can now:
1. See how many continuations are retryable at a glance
2. Understand exactly why any specific continuation is or isn't retryable
3. Take informed action based on clear diagnostic information

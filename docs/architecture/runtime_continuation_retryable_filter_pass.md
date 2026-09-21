# Runtime Continuation Retryable Filter Pass - Engineering Report

## Date: 2026-05-28

## Mission
Make actionable failed work discoverable efficiently at list level, without expensive per-row joins, so operators can quickly answer "which continuations can I retry right now?"

---

## Gap Analysis

### Previous State
After the execution-continuation linkage pass, operators could drill into a single failed execution and see its linked continuation's retry eligibility. However, there was no way to efficiently list only retryable continuations in bulk. Operators had to:
1. List all continuations (or filter by state)
2. Manually count which ones were retryable from the summary count
3. Open individual records to find retryable ones

### Problem Identified
The `GET /v1/continuations` endpoint already returned a `retryable` count in the response summary, but there was no way to filter the results to only show retryable (or non-retryable) continuations. This made bulk triage inefficient.

---

## Solution: Add `retryable` Filter to `GET /v1/continuations`

### Design Decision

**Chosen approach:** Add `retryable=true|false` as a composable secondary filter on `GET /v1/continuations`.

**Reasoning:**
1. **Efficiency** — `CanRetry()` is a simple boolean check on the continuation state + retry counters, no joins needed
2. **Operator workflow** — operators want to answer "what can I retry?" in bulk, not one-at-a-time
3. **Composability** — works with existing filters like `state=executed` to show "failed work I can still retry"
4. **Maps to action** — the filter directly corresponds to the `POST /v1/continuations/{id}/retry` action
5. **Existing pattern** — follows the same composable filter pattern as `action_type`, `environment`, etc.

### Implementation Details

**Filter logic:**

```go
if retryableFilter == "true" || retryableFilter == "false" {
    wantRetryable := retryableFilter == "true"
    filtered := make([]*continuation.Continuation, 0, len(continuations))
    for _, c := range continuations {
        if c.CanRetry() == wantRetryable {
            filtered = append(filtered, c)
        }
    }
    continuations = filtered
}
```

**Key behaviors:**
- Only applies when value is exactly `true` or `false` — invalid values are ignored (no filter applied)
- Reuses existing `CanRetry()` method — no new retry logic needed
- Applied after primary filters but before limit
- Summary counts (`retryable`, `executable`) are computed on the filtered set

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/continuations.go` — added `retryableFilter` parsing and filtering logic
- `docs/architecture/runtime_support_matrix.md` — documented new filter

### New Test Files
- (no new files — added 5 tests to `continuation_retry_diagnostics_test.go`)

---

## API Changes

### `GET /v1/continuations` Filter Addition

**New filter parameter:**
- `retryable=true` — only continuations where `CanRetry() == true`
- `retryable=false` — only continuations where `CanRetry() == false`

**Example queries:**
```
GET /v1/continuations?retryable=true
  → All retryable continuations

GET /v1/continuations?state=executed&retryable=true
  → Failed/completed continuations that can still be retried

GET /v1/continuations?state=executed&retryable=false
  → Failed/completed continuations that cannot be retried (exhausted, terminal, etc.)

GET /v1/continuations?retryable=true&action_type=shell
  → Retryable shell continuations
```

**Summary counts reflect filtered results:**
```json
{
  "continuations": [...],
  "count": 5,
  "executable": 0,
  "retryable": 5
}
```

---

## Tests Added

### Handler Tests (5 tests)
- `TestContinuationHandler_HandleList_FilterByRetryable_True` — filters to only retryable continuations
- `TestContinuationHandler_HandleList_FilterByRetryable_False` — filters to only non-retryable continuations
- `TestContinuationHandler_HandleList_CompositeFilter_StateAndRetryable` — combines `state=executed&retryable=true`
- `TestContinuationHandler_HandleList_RetryableFilter_NoMatch` — returns empty when no matches
- `TestContinuationHandler_HandleList_RetryableFilter_IgnoresInvalidValue` — invalid values are ignored (no filter applied)

**Total: 5 new tests**

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
- Could see `retryable=N` count in summary, but had to get all continuations and count manually
- Had to open individual records to find which specific continuations were retryable
- Could not efficiently list "non-retryable" continuations to understand what can't be recovered

### After This Pass
1. **Direct retryable listing** — `GET /v1/continuations?retryable=true` lists all actionable continuations
2. **Efficient failed-work triage** — `GET /v1/continuations?state=executed&retryable=true` shows exactly what can be retried
3. **Exhausted identification** — `GET /v1/continuations?retryable=false` shows what cannot be recovered
4. **Composable with existing filters** — works with `action_type`, `environment`, `agent_id`, etc.
5. **Summary reflects filtered set** — counts update based on filtered results

### Example Workflows

**Triage all failed work:**
```
1. GET /v1/continuations?state=executed&retryable=true
   → Returns all failed continuations that can be retried
   → Each includes retry diagnostics (retries_remaining, status)

2. For each, operator calls POST /v1/continuations/{id}/retry
```

**Understand what can't be recovered:**
```
1. GET /v1/continuations?state=executed&retryable=false
   → Returns failed continuations that cannot be retried
   → Shows which are exhausted vs terminal vs pending approval
```

**Prioritize by action type:**
```
1. GET /v1/continuations?retryable=true&action_type=shell
   → Returns only retryable shell commands
```

---

## Future Diagnostics/Recovery Work

1. **Bulk retry endpoint** — `POST /v1/continuations/retry?state=executed&retryable=true` to retry all matching
2. **Retry history tracking** — track previous execution IDs for audit trail
3. **Failure correlation** — group related failures by decision_id or agent_id
4. **Dead letter queue** — continuations that hit retry limit and cannot be recovered
5. **Auto-categorization improvements** — better failure categorization patterns

---

## Conclusion

This pass completes the bulk discoverability gap in the retry/recovery workflow. Combined with previous passes:

- **Single-item triage** — `GET /v1/executions/{id}` shows failure diagnostics AND linked continuation retry eligibility
- **Bulk discovery** — `GET /v1/continuations?retryable=true` lists all actionable continuations directly

Operators can now:
1. Discover retryable work in bulk without manual counting
2. Efficiently identify what cannot be recovered
3. Compose filters to narrow by state, action type, environment, agent
4. Take targeted action on individual records or batch operations

The `retryable` filter is efficient (no joins), composable, and directly maps to the recovery action — making it the highest-value next step for bulk actionability.

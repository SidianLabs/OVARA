# Runtime Actionable-Work Summary Pass - Engineering Report

## Date: 2026-05-28

## Mission
Add a compact actionable-work summary to `GET /v1/runtime/status` so operators can quickly understand backlog, failures, and recovery posture at a glance — without requiring clients to stitch together several filtered list calls.

---

## Gap Analysis

### Previous State
After the retryable filter pass, operators could list retryable continuations efficiently with `GET /v1/continuations?retryable=true`. However, the runtime status endpoint — the primary "at a glance" view of system health — did not expose retryable or executable counts for continuations. Operators had to make a separate API call just to know how much actionable work existed.

### Problem Identified
The runtime status endpoint already provided:
- `approvals` breakdown (pending, approved, denied)
- `continuations` breakdown (count, by_state)
- `executions` breakdown (total, succeeded, failed, running, timed_out)
- `queue_stats` (queued, running)

But it did not expose:
- `retryable` — how many continuations can be retried right now
- `executable` — how many continuations are ready for the queue

---

## Solution: Extend Continuation Summary in Runtime Status

### Design Decision

**Chosen approach:** Add `executable` and `retryable` counts to the `continuations` section of `GET /v1/runtime/status`.

**Reasoning:**
1. **One-stop health view** — operators can see all key counts (approvals, continuations, executions, queue) in a single response
2. **Efficiency** — both counts are computed in a single pass over `continuationStore.ListAll()`, no joins needed
3. **Clear semantics** — `executable` = approved/queued/ready; `retryable` = executed/resumed with retries remaining
4. **Follows existing pattern** — continuation section already had `count` and `by_state`, this extends it naturally
5. **No new endpoint** — avoids proliferation of near-similar endpoints

### Implementation Details

**Code change in `runtime.go`:**

```go
if h.continuationStore != nil {
    all := h.continuationStore.ListAll()
    stateCounts := make(map[string]int)
    var executableCount, retryableCount int
    for _, c := range all {
        stateCounts[string(c.State)]++
        if c.IsExecutable() {
            executableCount++
        }
        if c.CanRetry() {
            retryableCount++
        }
    }
    contStats := map[string]any{
        "count":       len(all),
        "by_state":    stateCounts,
        "executable":  executableCount,
        "retryable":   retryableCount,
    }
    // ... storage mode handling unchanged ...
}
```

**Key behaviors:**
- Both counts computed in same loop as `stateCounts` — no extra iteration
- `executable` = continuations where `IsExecutable() == true` (approved, queued, or ready)
- `retryable` = continuations where `CanRetry() == true` (executed or resumed with retries remaining)
- Nil-safe: only populated when `continuationStore` is set

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/runtime.go` — added `executable` and `retryable` counters to continuation stats
- `docs/architecture/runtime_support_matrix.md` — updated response example and added field documentation

### Updated Test Files
- `runtime/gateway/internal/handlers/runtime_status_comprehensive_test.go` — added assertions for new fields in existing test
- Added new test: `TestRuntimeStatusEndpoint_ContinuationRetryableExecutableCounts`

---

## API Changes

### `GET /v1/runtime/status` Response Change

**Before:**
```json
{
  "continuations": {
    "count": 5,
    "by_state": { "approved": 1, "queued": 1, "executed": 2, "denied": 1 }
  }
}
```

**After:**
```json
{
  "continuations": {
    "count": 5,
    "by_state": { "approved": 1, "queued": 1, "executed": 2, "denied": 1 },
    "executable": 2,
    "retryable": 1
  }
}
```

---

## Tests Added

### Updated Tests (1 test)
- `TestRuntimeStatusEndpoint_MixedState` — added assertions for `executable=2, retryable=0`

### New Tests (1 test)
- `TestRuntimeStatusEndpoint_ContinuationRetryableExecutableCounts` — verifies counts with varied continuation states including:
  - `executable` for approved and queued continuations
  - `retryable` for executed continuations with retries remaining
  - exhaustion for executed continuations at retry limit

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
- Had to call `GET /v1/continuations?retryable=true` just to know how many retryable continuations existed
- Could not see executable count in the status summary
- Could not get a complete "at a glance" view of actionable work

### After This Pass
Operators can answer these questions from a single `GET /v1/runtime/status` call:

| Question | Field |
|----------|-------|
| How many approvals need attention? | `approvals.pending` |
| How many continuations are queued or ready to run? | `continuations.executable` |
| How many continuations failed and can be retried? | `continuations.retryable` |
| How many executions failed or timed out? | `executions.failed`, `executions.timed_out` |
| Is the queue paused? | `queue_paused` |
| How many are queued vs running? | `queue_stats.queued`, `queue_stats.running` |

### Example Scenario

```
Operator calls GET /v1/runtime/status and sees:
  approvals.pending: 5
  continuations.executable: 12
  continuations.retryable: 3
  executions.failed: 2
  executions.timed_out: 1
  queue_paused: false

Interpretation:
- 5 approvals need human review
- 12 continuations are ready to execute
- 3 failed continuations can be retried (actionable recovery work)
- 2 failures + 1 timeout need investigation
- Queue is running normally
```

---

## Future Diagnostics/Recovery Work

1. **Bulk retry endpoint** — `POST /v1/continuations/retry?retryable=true` to retry all retryable continuations
2. **Failure correlation** — group failures by action_type, agent_id, or time window
3. **Dead letter queue view** — continuations at retry limit that need human intervention
4. **Alert thresholds** — configurable alerts when retryable or pending approval counts exceed thresholds
5. **Trend data** — historical counts for capacity planning (beyond scope of single-status endpoint)

---

## Conclusion

This pass completes the actionable-work visibility by adding `executable` and `retryable` counts to the runtime status endpoint. Combined with previous passes:

- **Single-call triage** — `GET /v1/executions/{id}` shows failure + continuation retry eligibility
- **Bulk discovery** — `GET /v1/continuations?retryable=true` lists all retryable continuations
- **At-a-glance summary** — `GET /v1/runtime/status` now shows actionable counts for approvals, executables, retryables, and failures

Operators can now assess system health and identify recovery workload in a single API call, then drill into specific items as needed.

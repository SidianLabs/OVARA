# Runtime Age/Staleness Summary Pass - Engineering Report

## Date: 2026-05-28

## Mission
Add compact age/staleness awareness to `GET /v1/runtime/status` so operators can quickly identify urgent backlog and neglected work — not just counts but how long items have been waiting.

---

## Gap Analysis

### Previous State
After the actionable-work summary pass, operators could see counts of pending approvals, executable continuations, and retryable continuations. However, there was no way to know how long the oldest items had been waiting. This left a gap:

- Could see `approvals.pending = 5` but not if the oldest has been waiting 3 days
- Could see `continuations.executable = 12` but not if some have been queued for hours
- Could see `continuations.retryable = 3` but not which ones are oldest and need priority attention

### Problem Identified
Operators needed age/staleness signals to:
1. Identify approvals that have been sitting too long unreviewed
2. Find executable continuations that have been waiting in the queue
3. Prioritize retry candidates that have failed the longest
4. Detect when failures are piling up without action

---

## Solution: Add Oldest Timestamps to Runtime Status

### Design Decision

**Chosen approach:** Add RFC3339 timestamp fields for oldest pending items in each category, directly in the existing status response sections.

**Reasoning:**
1. **Compact** — timestamps are small strings, not derived durations that would need refresh
2. **Timezone-agnostic** — RFC3339 includes timezone, operators can compute local age easily
3. **Nil-safe** — fields are omitted when no matching items exist, keeping the response clean
4. **No new endpoint** — extends existing status endpoint rather than creating a new one
5. **Efficient** — computed in same pass as existing counts, no extra iterations

### Implementation Details

**New fields added:**

| Section | Field | When Present |
|---------|-------|---------------|
| `approvals` | `oldest_pending_at` | When `pending > 0` |
| `continuations` | `oldest_executable_at` | When `executable > 0` |
| `continuations` | `oldest_retryable_at` | When `retryable > 0` |

**Timestamp semantics:**
- `approvals.oldest_pending_at` — `CreatedAt` of the oldest pending approval
- `continuations.oldest_executable_at` — `CreatedAt` of the oldest executable continuation
- `continuations.oldest_retryable_at` — `CreatedAt` of the oldest retryable continuation

**Code change (runtime.go):**

```go
// Approvals section
if len(pending) > 0 {
    var oldest time.Time
    for _, a := range pending {
        if oldest.IsZero() || a.CreatedAt.Before(oldest) {
            oldest = a.CreatedAt
        }
    }
    approvalStats["oldest_pending_at"] = oldest
}

// Continuations section (in same loop as counts)
var oldestExecutable, oldestRetryable time.Time
for _, c := range all {
    // ... count updates ...
    if c.IsExecutable() {
        // ...
        if oldestExecutable.IsZero() || c.CreatedAt.Before(oldestExecutable) {
            oldestExecutable = c.CreatedAt
        }
    }
    if c.CanRetry() {
        // ...
        if oldestRetryable.IsZero() || c.CreatedAt.Before(oldestRetryable) {
            oldestRetryable = c.CreatedAt
        }
    }
}
// Add to contStats only if > 0
if executableCount > 0 {
    contStats["oldest_executable_at"] = oldestExecutable
}
if retryableCount > 0 {
    contStats["oldest_retryable_at"] = oldestRetryable
}
```

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/runtime.go` — added oldest timestamp tracking to approval and continuation sections
- `docs/architecture/runtime_support_matrix.md` — updated response example and added field documentation

### Updated Test Files
- `runtime/gateway/internal/handlers/runtime_status_comprehensive_test.go` — added `time` import, added 2 new tests

---

## API Changes

### `GET /v1/runtime/status` Response Change

**Before:**
```json
{
  "approvals": { "pending": 5, "approved": 2, "denied": 1 },
  "continuations": { "count": 10, "executable": 3, "retryable": 2, ... }
}
```

**After:**
```json
{
  "approvals": {
    "pending": 5,
    "approved": 2,
    "denied": 1,
    "oldest_pending_at": "2026-05-28T10:30:00Z"
  },
  "continuations": {
    "count": 10,
    "executable": 3,
    "retryable": 2,
    "oldest_executable_at": "2026-05-28T12:00:00Z",
    "oldest_retryable_at": "2026-05-28T11:00:00Z",
    ...
  }
}
```

**Note:** Oldest timestamp fields are omitted when there are no matching items.

---

## Tests Added

### New Tests (2 tests)
- `TestRuntimeStatusEndpoint_OldestTimestamps` — verifies timestamps are correctly populated for approvals, executable continuations, and retryable continuations
- `TestRuntimeStatusEndpoint_OldestTimestamps_OmitWhenEmpty` — verifies timestamps are omitted when no matching items exist

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
- Could see counts of pending, executable, retryable items
- Had to make additional API calls or check logs to know how long items had been waiting
- Could not easily identify which items were "stale" vs recently added

### After This Pass
Operators can answer these questions from a single `GET /v1/runtime/status` call:

| Question | Field |
|----------|-------|
| How old is the oldest pending approval? | `approvals.oldest_pending_at` |
| How old is the oldest executable continuation? | `continuations.oldest_executable_at` |
| How old is the oldest retryable continuation? | `continuations.oldest_retryable_at` |
| Are there any pending approvals at all? | `approvals.pending > 0` |
| Are there any retryable continuations? | `continuations.retryable > 0` |

### Example Scenario

```
Operator calls GET /v1/runtime/status and sees:
  approvals.pending: 5
  approvals.oldest_pending_at: "2026-05-25T10:00:00Z"  (3 days old!)
  continuations.executable: 12
  continuations.oldest_executable_at: "2026-05-28T08:00:00Z"  (4 hours ago)
  continuations.retryable: 3
  continuations.oldest_retryable_at: "2026-05-27T14:00:00Z"  (yesterday)

Interpretation:
- 5 pending approvals exist, but the oldest is 3 days old — urgent attention needed
- 12 executable continuations, oldest is 4 hours — normal queue depth
- 3 retryable failures, oldest is from yesterday — recovery work is not piling up critically
```

---

## Future Diagnostics/Recovery Work

1. **SLA thresholds** — configurable alerts when oldest timestamps exceed thresholds (e.g., pending > 24h)
2. **Bulk age sorting** — `GET /v1/continuations?sort=oldest` to list by creation time
3. **Trend analysis** — track how oldest timestamps change over time (beyond single-status scope)
4. **Expired continuations** — expose `ExpiresAt` for continuations that may expire soon
5. **Queue wait times** — track time between `ApprovedAt` and `QueuedAt` for queue latency

---

## Conclusion

This pass adds age/staleness awareness to the runtime status endpoint, completing the visibility picture. Combined with previous passes:

- **Counts** — `GET /v1/runtime/status` shows counts for approvals, continuations, executions
- **Actionability** — `executable` and `retryable` counts show what's actionable
- **Age/Staleness** — `oldest_*_at` timestamps show how long work has been waiting

Operators can now triage by urgency: a 3-day-old pending approval is more urgent than a 5-minute-old one. The oldest timestamp fields are compact, nil-safe, and computed efficiently in the same pass as existing counts.

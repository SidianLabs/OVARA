# Runtime Age-Based Filtering Pass - Engineering Report

## Date: 2026-05-28

## Mission
Add age-based filtering to approval and continuation list endpoints so operators can isolate stale work directly — filtering by creation timestamp without fetching and scanning broad result sets.

---

## Gap Analysis

### Previous State
After the list prioritization pass, operators could sort by oldest/newest but still had to retrieve all items and filter client-side to isolate stale work. This was inefficient for large result sets.

### Problem Identified
Operators needed to:
1. Find approvals older than a specific date
2. Find continuations created before a certain time
3. Combine age filtering with existing filters (status, retryable, etc.)

Without server-side age filtering, operators had to fetch all items and filter client-side — inefficient and unscalable.

---

## Solution: Add `created_before` and `created_after` Filters

### Design Decision

**Chosen approach:** RFC3339 timestamp filters `created_before` and `created_after` on both list endpoints.

**Reasoning:**
1. **RFC3339 is already used** — `oldest_pending_at` etc. in status responses use RFC3339 format
2. **Unambiguous semantics** — exact timestamp cutoff, no reference-time confusion
3. **Timezone-aware** — RFC3339 includes timezone information
4. **Composable** — works with all existing filters and sorting
5. **Backward compatible** — invalid values are ignored (no error returned)

### Implementation Details

**Both handlers:**
```go
createdBefore := r.URL.Query().Get("created_before")
createdAfter := r.URL.Query().Get("created_after")

if createdBefore != "" {
    if t, err := time.Parse(time.RFC3339, createdBefore); err == nil {
        filtered := make([]*Item, 0, len(items))
        for _, item := range items {
            if item.CreatedAt.Before(t) || item.CreatedAt.Equal(t) {
                filtered = append(filtered, item)
            }
        }
        items = filtered
    }
}

if createdAfter != "" {
    if t, err := time.Parse(time.RFC3339, createdAfter); err == nil {
        filtered := make([]*Item, 0, len(items))
        for _, item := range items {
            if item.CreatedAt.After(t) {
                filtered = append(filtered, item)
            }
        }
        items = filtered
    }
}
```

**Key behaviors:**
- Parsing errors are silently ignored (backward compatible)
- `created_before` includes items where CreatedAt <= cutoff
- `created_after` includes items where CreatedAt > cutoff
- Both filters can be used together for time ranges
- Filters applied after existing filters, before sort and limit

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/approval.go` — added `time` import, `createdBefore`, `createdAfter` params, and filtering logic
- `runtime/gateway/internal/handlers/continuations.go` — same changes as approvals
- `docs/architecture/runtime_support_matrix.md` — documented new filter parameters and added examples

### Updated Test Files
- `runtime/gateway/internal/handlers/polish_verification_test.go` — added 7 new tests

---

## API Changes

### `GET /v1/approvals` Filter Addition

**New filter parameters:**
- `created_before=<RFC3339>` — include items created at or before this time
- `created_after=<RFC3339>` — include items created after this time

**Example queries:**
```
GET /v1/approvals?status=pending&created_before=2026-05-25T00:00:00Z
  → Pending approvals created before May 25th

GET /v1/approvals?created_after=2026-05-27T00:00:00Z&sort=oldest
  → Approvals created after May 27th, oldest first
```

### `GET /v1/continuations` Filter Addition

**New filter parameters:**
- `created_before=<RFC3339>` — include items created at or before this time
- `created_after=<RFC3339>` — include items created after this time

**Example queries:**
```
GET /v1/continuations?retryable=true&created_before=2026-05-20T00:00:00Z
  → Retryable continuations created before May 20th

GET /v1/continuations?created_after=2026-05-27T00:00:00Z&sort=newest
  → Continuations created after May 27th, newest first
```

---

## Tests Added

### Handler Tests (7 tests)
- `TestApprovalHandler_ListApprovals_CreatedBefore` — verifies filtering by created_before
- `TestApprovalHandler_ListApprovals_CreatedAfter` — verifies filtering by created_after
- `TestApprovalHandler_ListApprovals_CreatedBeforeInvalid` — verifies invalid timestamps are ignored
- `TestContinuationHandler_HandleList_CreatedBefore` — verifies filtering by created_before
- `TestContinuationHandler_HandleList_CreatedAfter` — verifies filtering by created_after
- `TestContinuationHandler_HandleList_CreatedBeforeWithSort` — verifies created_before composes with sort
- `TestContinuationHandler_HandleList_CreatedBeforeInvalid` — verifies invalid timestamps are ignored

**Total: 7 new tests**

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
- Could see oldest timestamps in runtime status
- Could sort by oldest/newest
- Had to fetch all items client-side to filter by age

### After This Pass
Operators can efficiently isolate stale work directly:

| Query | Use Case |
|-------|----------|
| `?created_before=2026-05-20T00:00:00Z` | Items older than a specific date |
| `?created_after=2026-05-27T00:00:00Z` | Items newer than a specific date |
| `?retryable=true&created_before=<cutoff>` | Stale retryable items |
| `?status=pending&created_before=<cutoff>` | Stale pending approvals |
| `&sort=oldest&created_before=<cutoff>` | Oldest stale items first |

### Example Workflow

```
1. Operator sees oldest_pending_at = "2026-05-25T10:00:00Z" in status
   → Knows there are approvals from May 25th

2. Operator fetches only those stale approvals:
   GET /v1/approvals?status=pending&created_before=2026-05-26T00:00:00Z
   → Only returns approvals created before May 26th

3. Combined with sort for prioritization:
   GET /v1/approvals?status=pending&created_before=2026-05-26T00:00:00Z&sort=oldest
   → Oldest stale approvals first
```

---

## Future Diagnostics/Recovery Work

1. **Bulk retry with age filter** — `POST /v1/continuations/retry?retryable=true&created_before=<cutoff>` to retry stale items
2. **Auto-expiration detection** — filter by `expires_before` for continuations nearing expiration
3. **Trend analysis** — track creation rates over time windows
4. **SLA breach detection** — combine age filtering with action_type or environment
5. **Time-window analytics** — items created in specific ranges (last hour, today, this week)

---

## Conclusion

This pass adds server-side age filtering, completing the staleness pipeline:

- **Summary signals** — `GET /v1/runtime/status` shows oldest timestamps
- **Prioritized retrieval** — `GET /v1/approvals?sort=oldest` / `GET /v1/continuations?sort=oldest`
- **Age-based filtering** — `created_before` / `created_after` isolate stale work directly

Operators can now move from "I see there's old work" to "here are exactly the items older than my threshold" in a single API call — without fetching and scanning all items client-side.

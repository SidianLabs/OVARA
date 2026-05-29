# Runtime Limit+Sort Interaction Fix - Engineering Report

## Date: 2026-05-28

## Mission
Fix the limit+sort interaction bug in approval and continuation list handlers where `limit` was applied from the end of the sorted slice instead of the beginning, causing counterintuitive results.

---

## Gap Analysis

### Bug Identified
All list handlers applied `limit` by slicing from the end of the sorted slice:

```go
if limit > 0 && len(items) > limit {
    items = items[len(items)-limit:]
}
```

This caused a counterintuitive interaction with `sort`:
- `sort=newest&limit=10` returned the **oldest** 10 items (should be newest)
- `sort=oldest&limit=10` returned the **newest** 10 items (should be oldest)

### Root Cause
When `sort=newest` is applied, newest items are at index 0 and oldest at the end. Taking from the end (`[len-limit:]`) gives the oldest items, not the newest. Similarly for `sort=oldest`.

### Impact
- Operators relying on `sort=newest&limit=N` to get the N most recent items would receive the N oldest items instead
- This affected `GET /v1/approvals` and `GET /v1/continuations` (execution handler has no sort)

---

## Solution

### Fix
Change limit logic to always take from the beginning of the sorted slice:

```go
if limit > 0 && len(items) > limit {
    items = items[:limit]
}
```

With this fix:
- `sort=newest` puts newest first → `[:limit]` returns newest items ✓
- `sort=oldest` puts oldest first → `[:limit]` returns oldest items ✓

### Files Modified

**`runtime/gateway/internal/handlers/approval.go`:**
- Changed limit logic from `items[len(items)-limit:]` to `items[:limit]`

**`runtime/gateway/internal/handlers/continuations.go`:**
- Changed limit logic from `items[len(items)-limit:]` to `items[:limit]`

### Note on Execution Handler
The execution handler (`GET /v1/executions`) does not have a `sort` parameter, so it continues to use `items[len(items)-limit:]` which returns the most recently created items (since store iteration order correlates with creation order). This is correct and unchanged.

> **Correction (2026-05-29):** The claim above is inaccurate. All stores back their
> list methods with Go map iteration, which is randomized — iteration order does **not**
> correlate with creation order. As a result `items[len(items)-limit:]` returned an
> arbitrary, non-reproducible subset, not the most recent items. This was fixed in the
> deterministic list ordering pass (`runtime_list_ordering_pass.md`), which gives all
> list endpoints a stable default sort (newest first) applied before `limit`, and adds
> a `sort` parameter to `GET /v1/executions`.

---

## Test Coverage

Added 4 new tests in `runtime/gateway/internal/handlers/polish_verification_test.go`:

1. **`TestContinuationHandler_HandleList_LimitWithSortOldest`** — verifies `sort=oldest&limit=3` returns 3 oldest items (dec_e, dec_d, dec_c)
2. **`TestContinuationHandler_HandleList_LimitWithSortNewest`** — verifies `sort=newest&limit=3` returns 3 newest items (dec_a, dec_b, dec_c)
3. **`TestApprovalHandler_ListApprovals_LimitWithSortOldest`** — same for approvals
4. **`TestApprovalHandler_ListApprovals_LimitWithSortNewest`** — same for approvals

---

## Verification

All tests pass including race detector:

```
go build ./...   ✓
go vet ./...     ✓
go test ./...    ✓
go test -race ./... ✓
```

---

## Behavior Summary

| Query | Old Behavior (Bug) | New Behavior (Correct) |
|-------|---------------------|------------------------|
| `?sort=newest&limit=3` | Oldest 3 items | Newest 3 items |
| `?sort=oldest&limit=3` | Newest 3 items | Oldest 3 items |
| `?limit=3` (no sort) | Newest 3 items | Newest 3 items |

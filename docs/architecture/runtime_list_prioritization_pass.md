# Runtime List Prioritization Pass - Engineering Report

## Date: 2026-05-28

## Mission
Add list prioritization capability to approval and continuation endpoints so operators can retrieve oldest items first — turning summary staleness signals into actionable item discovery.

---

## Gap Analysis

### Previous State
After the age/staleness summary pass, operators could see `oldest_pending_at`, `oldest_executable_at`, and `oldest_retryable_at` timestamps in the runtime status. However, they had no way to efficiently retrieve the actual items ordered by age. List endpoints returned items in undefined map-iteration order.

### Problem Identified
Operators needed to:
1. Get the oldest pending approvals after seeing `approvals.oldest_pending_at` in status
2. Get the oldest retryable continuations after seeing `continuations.oldest_retryable_at` in status
3. Prioritize their review queue by age without manual scanning

The list endpoints had `limit` but no `sort`, and returned items in non-deterministic order.

---

## Solution: Add `sort` Parameter to List Endpoints

### Design Decision

**Chosen approach:** Add `sort=oldest` / `sort=newest` as a composable filter parameter to both `GET /v1/approvals` and `GET /v1/continuations`.

**Reasoning:**
1. **Operator workflow** — natural to ask "show me oldest pending approvals first"
2. **Composable with existing filters** — works with `status=pending`, `retryable=true`, etc.
3. **Clear semantics** — `oldest` = oldest CreatedAt first, `newest` = newest first
4. **Backward compatible** — default (no sort) preserves existing undefined-order behavior
5. **Efficient** — sorting is done in-memory after filtering, no extra queries

### Implementation Details

**Added to both handlers:**
```go
sortOrder := r.URL.Query().Get("sort")

if sortOrder == "oldest" {
    sort.Slice(items, func(i, j int) bool {
        return items[i].CreatedAt.Before(items[j].CreatedAt)
    })
} else if sortOrder == "newest" {
    sort.Slice(items, func(i, j int) bool {
        return items[j].CreatedAt.Before(items[i].CreatedAt)
    })
}
```

**Key behaviors:**
- Sorting happens after all filters, before limit
- Invalid sort values are ignored (backward compatible)
- Default (no sort) preserves existing undefined order
- Works with all existing filter combinations

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/approval.go` — added `sort` import, `sortOrder` parsing, and sort logic
- `runtime/gateway/internal/handlers/continuations.go` — added `sort` import, `sortOrder` parsing, and sort logic
- `docs/architecture/runtime_support_matrix.md` — documented `sort` parameter for both endpoints

### Updated Test Files
- `runtime/gateway/internal/handlers/polish_verification_test.go` — added 6 new sort tests

---

## API Changes

### `GET /v1/approvals` Filter Addition

**New filter parameter:**
- `sort=oldest` — order by CreatedAt ascending (oldest first)
- `sort=newest` — order by CreatedAt descending (newest first)

**Example queries:**
```
GET /v1/approvals?status=pending&sort=oldest
  → Oldest pending approvals first

GET /v1/approvals?sort=newest
  → Newest approvals first
```

### `GET /v1/continuations` Filter Addition

**New filter parameter:**
- `sort=oldest` — order by CreatedAt ascending (oldest first)
- `sort=newest` — order by CreatedAt descending (newest first)

**Example queries:**
```
GET /v1/continuations?retryable=true&sort=oldest
  → Oldest retryable continuations first

GET /v1/continuations?state=executed&sort=newest
  → Most recently executed continuations first
```

---

## Tests Added

### Handler Tests (6 tests)
- `TestApprovalHandler_ListApprovals_SortOldest` — verifies oldest-first ordering
- `TestApprovalHandler_ListApprovals_SortNewest` — verifies newest-first ordering
- `TestApprovalHandler_ListApprovals_SortWithFilter` — verifies sort composes with action_type filter
- `TestContinuationHandler_HandleList_SortOldest` — verifies oldest-first ordering
- `TestContinuationHandler_HandleList_SortNewest` — verifies newest-first ordering
- `TestContinuationHandler_HandleList_SortWithRetryableFilter` — verifies sort composes with retryable filter

**Total: 6 new tests**

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
- Had to retrieve all items and manually sort to find oldest
- List order was undefined and non-deterministic

### After This Pass
Operators can efficiently retrieve prioritized work:

| Query | Use Case |
|-------|----------|
| `GET /v1/approvals?status=pending&sort=oldest` | Review oldest pending approvals first |
| `GET /v1/continuations?retryable=true&sort=oldest` | Address oldest failures first |
| `GET /v1/continuations?state=executed&sort=newest` | See most recent failures |
| `GET /v1/approvals?environment=production&sort=oldest` | Prioritize production escalations |

### Example Workflow

```
1. Operator calls GET /v1/runtime/status
   → approvals.oldest_pending_at = "2026-05-25T10:00:00Z" (3 days old!)
   → continuations.retryable = 3
   → continuations.oldest_retryable_at = "2026-05-27T14:00:00Z"

2. Operator fetches oldest pending approvals:
   GET /v1/approvals?status=pending&sort=oldest
   → Returns pending approvals ordered oldest first

3. Operator fetches oldest retryable continuations:
   GET /v1/continuations?retryable=true&sort=oldest
   → Returns retryable continuations ordered oldest first

4. Operator can now prioritize work systematically
```

---

## Future Diagnostics/Recovery Work

1. **Bulk retry endpoint** — `POST /v1/continuations/retry?retryable=true&sort=oldest` to retry all retryable, oldest first
2. **Approval urgency scoring** — combine age with trust_level/action_type for smart prioritization
3. **Pagination with cursors** — efficient pagination over large result sets
4. **SLA-aware sorting** — highlight items exceeding expected wait times
5. **Trend analysis** — track how oldest timestamps evolve over time

---

## Conclusion

This pass completes the staleness-to-action pipeline:

- **Summary signals** — `GET /v1/runtime/status` shows oldest timestamps
- **Prioritized discovery** — `GET /v1/approvals?sort=oldest` and `GET /v1/continuations?sort=oldest` retrieve items in age order
- **Composable** — sort works with all existing filters

Operators can now move from "I see there's old work" to "here's the specific oldest item I should act on" in a single API call.

# Runtime List Ordering Pass - Engineering Report

## Date: 2026-05-29

## Mission
Make the operator list endpoints return a **deterministic, meaningful** order by default so that `limit` returns a reproducible "most recent N" window instead of an arbitrary subset. Add the missing `sort` parameter to `GET /v1/executions` and bring all list endpoints onto a single, shared limit/sort contract.

---

## What I Verified From Prior Context

Before making changes I reconciled the handoff against the code on disk:

- **Branch/state:** on `phase-64-v1-polish` with a large body of uncommitted polish work. `go build ./...`, `go test ./...`, `go vet ./...`, and `go test -race` on the touched packages were all green at the start.
- **Action types:** `models/action_request.go` defines the expected surfaces — `shell`, `exec`, `git.push`, `git.pull`, `git.fetch`, `git.checkout` (plus interceptor-only types like `git.force_push`, `github.*`, `ci.*` that are not registered for execution).
- **Registry wiring:** `cmd/server/main.go` registers `shell`, `exec`, and the four git actions into the `ExecutorRegistry`, and starts the orchestrator with that set. Matches the handoff.
- **Handlers:** approvals, continuations, executions, and runtime status all exist with the documented filters (`status`, `state`, `agent_id`, `decision_id`, `approval_id`, `environment`, `action_type`, `retryable`, `sort`, `created_before`, `created_after`, `limit`) and response shapes (summary counts, retry/failure diagnostics, oldest timestamps).

Everything in the handoff matched the code, so no rediscovery was wasted.

---

## Gap Analysis (the real defect)

While verifying the list endpoints I found a concrete, operator-facing correctness bug that the prior `runtime_limit_sort_fix_pass.md` had mischaracterized.

### Root cause
Every store backs its list methods (`ListAll`, `ListByState`, `ListByStatus`, etc.) with **Go map iteration**, which is deliberately randomized:

```go
func (s *InMemoryStore) ListAll() []*ApprovalRequest {
    result := make([]*ApprovalRequest, 0, len(s.items))
    for _, req := range s.items { // map iteration: random order
        result = append(result, req)
    }
    return result
}
```

The prior report claimed executions used `items[len(items)-limit:]` to return "the most recently created items (since store iteration order correlates with creation order)." **That assumption is false** — map iteration order has no relationship to insertion order.

### Impact
- `GET /v1/executions?limit=100` over 500 executions returned a **random** 100, not the most recent 100.
- `GET /v1/approvals` and `GET /v1/continuations` with no `sort` returned a non-reproducible subset under `limit`.
- Truncation direction was inconsistent: approvals/continuations took the head (`[:limit]`), executions took the tail (`[len-limit:]`).
- `GET /v1/executions` had no `sort` parameter at all, unlike the other two.
- `GET /v1/continuations/queue` (a scheduling view that should be FIFO) was also map-ordered.

This directly undermined the staleness/prioritization work from earlier passes: an operator who saw `oldest_pending_at` in status and then paged a list could get inconsistent results between calls.

---

## Solution

### Shared contract (`internal/handlers/listing.go`)
New helpers centralize the policy:

- `parseLimit(r, def, max)` — single implementation of limit parsing, clamping to `(0, max]` with fallback to `def` for missing/invalid/non-positive values.
- `sortAscending(sortOrder)` — `sort=oldest` ⇒ ascending; everything else (including empty) ⇒ descending (newest first).
- `defaultListLimit = 100`, `maxListLimit = 1000` constants replace the duplicated literals.

### Deterministic ordering, applied after filters, before limit
Each list handler now always sorts before limiting, with a stable ID tiebreaker:

- **Approvals** — by `CreatedAt`, tiebreak `ApprovalID`. Default newest first.
- **Continuations** — by `CreatedAt`, tiebreak `ContinuationID`. Default newest first. Sort moved to **after** the `created_before`/`created_after` filters (previously it ran before them, which was harmless but ordering-fragile).
- **Executions** — by `StartedAt`, tiebreak `ExecutionID` (the tiebreaker also gives pending executions, whose `StartedAt` is zero, a stable order). New `sort` parameter added.
- **Queue** (`/v1/continuations/queue`) — FIFO by `QueuedAt` (falling back to `CreatedAt`), tiebreak `ContinuationID`.

All endpoints now take the head (`[:limit]`) of the sorted slice, so `sort=newest&limit=N` returns the newest N and `sort=oldest&limit=N` returns the oldest N — consistently.

### Backward compatibility
- `sort=oldest` / `sort=newest` behave exactly as before for callers that pass them.
- The only behavior change for callers that omit `sort` is that the order is now defined (newest first) and stable instead of random — a strict improvement. No existing test asserted a specific default order without a `sort` param (verified).

---

## Files Changed

### New
- `runtime/gateway/internal/handlers/listing.go` — shared `parseLimit` / `sortAscending` helpers and limit constants.
- `runtime/gateway/internal/handlers/list_ordering_test.go` — 8 tests covering the new contract.

### Modified
- `runtime/gateway/internal/handlers/approval.go` — use `parseLimit`; deterministic default sort with `ApprovalID` tiebreak after timestamp filters; dropped now-unused `strconv` import.
- `runtime/gateway/internal/handlers/continuations.go` — use `parseLimit`; deterministic default sort with `ContinuationID` tiebreak after timestamp filters; FIFO ordering for the queue listing.
- `runtime/gateway/internal/handlers/execution.go` — use `parseLimit`; added `sort` parameter and deterministic default sort with `ExecutionID` tiebreak; dropped now-unused `strconv` import.
- `docs/architecture/runtime_support_matrix.md` — documented the shared "List Endpoint Ordering Contract", updated approvals/continuations/executions filter docs, and added the executions `sort` parameter.
- `docs/architecture/runtime_limit_sort_fix_pass.md` — appended a correction noting the earlier "iteration order correlates with creation order" claim was inaccurate.

---

## Tests Added (8)

In `list_ordering_test.go`:
1. `TestContinuationHandler_HandleList_DefaultOrderNewestFirst`
2. `TestContinuationHandler_HandleList_LimitReturnsNewestDeterministically` — runs twice and asserts the same result both times (proves it is no longer random).
3. `TestApprovalHandler_ListApprovals_DefaultOrderNewestFirst`
4. `TestExecutionHandler_ListExecutions_DefaultOrderNewestFirst`
5. `TestExecutionHandler_ListExecutions_SortOldest`
6. `TestExecutionHandler_ListExecutions_SortNewestWithLimit`
7. `TestParseLimit_DefaultsAndCaps` — defaults, non-positive, non-numeric, and max-cap clamping.
8. `TestContinuationHandler_HandleQueue_FIFOOrder`

All insert items out of order so a passing test cannot be a map-iteration coincidence.

---

## Verification

```bash
cd runtime/gateway
go build ./...                                            # pass
go vet ./...                                              # pass
go test ./...                                             # pass
go test -race ./internal/handlers/ ./internal/continuation/ \
              ./internal/approval/ ./internal/execution/  # pass
```

The existing handler suite (including the prior sort/limit/created_before tests) continues to pass unchanged.

---

## Remaining Risks / Next Best Follow-ups

- **Sort cost is O(n log n) on every list call.** For the local-first scale this targets (thousands of records, capped at `maxListLimit`), this is negligible. If record counts ever grow large, a store-level ordered index would be the next step — but that is not justified by current evidence.
- **No cursor pagination.** `limit` still returns a single capped window with no continuation token. If operators need to walk large result sets page-by-page, cursor-based pagination keyed on `(timestamp, id)` is the natural follow-up and now has a deterministic order to build on.
- **Bulk retry workflow** (`POST /v1/continuations/retry?retryable=true&sort=oldest`) remains an attractive next operator capability; the deterministic `sort=oldest` ordering established here is a prerequisite for making "retry the oldest failures first" predictable.

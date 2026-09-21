# Runtime Visibility Pass 2: Continuation & Execution Inspection

**Date:** 2026-05-28
**Pass:** Operator Inspection Surface (Continuation + Execution)
**Status:** Complete

## Summary

Expanded operator inspection capabilities for continuations and executions, bringing parity with the previously added approval listing. Both `GET /v1/continuations` and `GET /v1/executions` now support composable filters. The continuation handler now returns full model data instead of a hand-projected map.

## Problem Statement

Both handlers had significant inspection gaps:

**Continuation handler gaps:**
- Only one of `state`, `agent_id`, or `decision_id` could be set at a time — filters were mutually exclusive
- `action_type`, `environment`, and `approval_id` not exposed despite model/store support
- Response was a hand-projected map (15+ model fields dropped from list view)
- Empty results returned `nil` instead of `[]`

**Execution handler gaps:**
- `decision_id` param existed but the store method (`ListByDecision`) was never wired up
- `action_type` secondary filter not implemented
- Empty results returned `nil` instead of `[]`

## Changes

### `internal/handlers/execution.go` — `handleList`

**Added params:**
- `decision_id` — wired to `ListByDecision(decisionFilter)` as a primary filter (after `continuation_id`, before `ListAll()`)
- `action_type` — in-memory secondary filter applied after primary filter

**Empty result guard:**
- Added `if execs == nil { execs = []*execution.Execution{} }` to ensure consistent array response

### `internal/handlers/continuations.go` — `handleList`

**Added params:**
- `action_type` — in-memory secondary filter
- `environment` — in-memory secondary filter
- `approval_id` — in-memory secondary filter

**Filter redesign:**
- Primary filters remain mutually exclusive (`state`, `agent_id`, `decision_id`)
- Secondary filters (`approval_id`, `environment`, `action_type`) are applied in a second pass regardless of which primary filter ran — enables composable queries like `?state=approved&agent_id=agt_x`

**Response redesign:**
- Replaced hand-projected `enriched` map with direct `continuation.Continuation` serialization — operators get all model fields in list view now
- Removed `executableCount()` helper and computed `executable` count inline
- Added nil guard for empty results

### `internal/handlers/execution_test.go` — New tests

- `TestExecutionHandler_ListExecutions_FilterByDecision`
- `TestExecutionHandler_ListExecutions_FilterByActionType`
- `TestExecutionHandler_ListExecutions_FilterByStateAndActionType`
- `TestExecutionHandler_ListExecutions_EmptyResult`

### `internal/handlers/continuation_test.go` — New tests

- `TestContinuationHandler_HandleList_FilterByActionType`
- `TestContinuationHandler_HandleList_FilterByEnvironment`
- `TestContinuationHandler_HandleList_FilterByApprovalID`
- `TestContinuationHandler_HandleList_CompositeFilters`
- `TestContinuationHandler_HandleList_EmptyResult`

### `docs/architecture/runtime_lifecycle.md`

Added new sections documenting the inspection endpoints for both continuations and executions.

## Filtering Design

### Execution filter priority

```
continuation_id != "" → ListByContinuation
state != ""           → ListByState
decision_id != ""     → ListByDecision
else                  → ListAll
```
Then apply `action_type` secondary in-memory filter if set.

### Continuation filter priority

```
decision_id != ""  → ListByDecision
agent_id != ""     → ListByAgent
state != ""        → ListByState
else               → ListAll
```
Then apply `approval_id`, `environment`, `action_type` (in that order) as composable secondary filters regardless of which primary filter ran.

This is consistent with the approvals approach from the first visibility pass.

## What Operators Can Now Inspect

| What | How |
|------|-----|
| All continuations | `GET /v1/continuations` |
| Escalated/approved/queued/ready etc | `GET /v1/continuations?state=approved` |
| Continuations by agent | `GET /v1/continuations?agent_id=agt_x` |
| Continuations by decision | `GET /v1/continuations?decision_id=dec_abc` |
| Continuations by approval | `GET /v1/continuations?approval_id=apr_abc` |
| Continuations in env | `GET /v1/continuations?environment=production` |
| Continuations by action type | `GET /v1/continuations?action_type=shell` |
| Composable: approved + agent | `GET /v1/continuations?state=approved&agent_id=agt_x` |
| All executions | `GET /v1/executions` |
| Executions by state | `GET /v1/executions?state=failed` |
| Executions by continuation | `GET /v1/executions?continuation_id=cnt_abc` |
| Executions by decision | `GET /v1/executions?decision_id=dec_abc` |
| Executions by action type | `GET /v1/executions?action_type=exec` |
| Composable: failed + shell | `GET /v1/executions?state=failed&action_type=shell` |

## Verification

- `go build ./...` — passes
- `go vet ./...` — passes
- `go test ./...` — all packages pass (including 5 new execution tests + 5 new continuation tests)
- `go test -race ./...` — all packages pass

## Files Modified

- `runtime/gateway/internal/handlers/execution.go` — `decision_id` filter + `action_type` secondary + nil guard
- `runtime/gateway/internal/handlers/continuations.go` — composable secondary filters + full model response
- `runtime/gateway/internal/handlers/execution_test.go` — 4 new tests
- `runtime/gateway/internal/handlers/continuation_test.go` — 5 new tests + rewritten file
- `docs/architecture/runtime_lifecycle.md` — documentation for all inspection endpoints

## What Remains for Future Visibility

- No sorting control (`sort_by`, `order`)
- No pagination (`offset`, `cursor`, `page_token`) — all list endpoints do tail truncation only
- No time-range filters on `created_at`/`started_at` fields despite events handler demonstrating the pattern with `since`/`until`
- No `GET /v1/approvals/stats` endpoint (approval store has `Stats()` but no handler wires it)
- `GET /v1/continuations/stats` iterates `ListAll()` manually while FileBackedStore has unused `CountByState()` method
- Execution handler does not expose `ListByApprovalID` — no store method exists to add it
- Continuation list response could include `is_executable` and `time_to_expiry` computed fields (previously present in hand-projected map but stripped from full model response)

# Runtime Visibility Pass: Approval Queue Inspection

**Date:** 2026-05-28
**Pass:** Operator Inspection Surface
**Status:** Complete

## Summary

Added `GET /v1/approvals` endpoint with filter support for status, requester (decision_id), environment, and action_type. Also added `ListAll` to the approval store/service layer to support unfiltered listing.

## Problem Statement

The existing approval endpoint only supported `GET /v1/approval/pending` which returned only pending approvals with no filtering. Operators needed to inspect the full approval history with the ability to filter by various dimensions.

## Changes

### New Endpoint

**`GET /v1/approvals`** — List all approvals with optional filtering

Query parameters:
- `status` — Filter by approval status (`pending`, `approved`, `denied`)
- `requester` — Filter by decision ID (the escalation requester)
- `environment` — Filter by environment (`local`, `dev`, `staging`, `production`)
- `action_type` — Filter by action type (`shell`, `exec`, `git.push`, `git.pull`, `git.fetch`, `git.checkout`)
- `limit` — Cap results (max 1000, default 100)

Response format:
```json
{
  "approvals": [...],
  "count": N
}
```

### Store Layer

Added `ListAll()` method to `approval.Store` interface and implemented in both `InMemoryStore` and `FileBackedStore`.

**`internal/approval/store.go`:**
- Added `ListAll() []*ApprovalRequest` to `Store` interface

**`internal/approval/file_store.go`:**
- Added `ListAll()` implementation

**`internal/approval/service.go`:**
- Added `ListAll()` wrapper method

### Handler

**`internal/handlers/approval.go`:**
- Registered new route `GET /v1/approvals` → `handleListApprovals`
- Implemented `handleListApprovals` with cascading filter support (status/requester are primary filters, environment/action_type are secondary filters applied to the result set)
- Added `strconv` import for limit parsing

### Tests

**`internal/handlers/polish_verification_test.go`:**
- Added `TestApprovalHandler_ListApprovals` with 7 subtests:
  1. `list_all_approvals_returns_all_items`
  2. `filter_by_status_returns_matching_approvals`
  3. `filter_by_requester_returns_matching_approvals`
  4. `filter_by_environment_returns_matching_approvals`
  5. `filter_by_action_type_returns_matching_approvals`
  6. `limit_parameter_caps_results`
  7. `empty_result_returns_empty_array`

**`internal/integrity/checker_test.go`:**
- Added `ListAll()` to `mockApprovalStore` to satisfy updated interface

## Design Decisions

1. **Filter priority:** Status and requester are primary filters (mutually exclusive — if status is set, requester is ignored). Environment and action_type are secondary filters applied to whatever the primary filter returns. This is consistent with how the executions endpoint handles filtering.

2. **Limit enforcement position:** Limit is applied after all filters, capping the final result set. This is consistent with the executions endpoint behavior.

3. **Empty array for empty results:** When no approvals match, returns `{"approvals": [], "count": 0}` rather than `null`. Consistent with `handleListPending` behavior.

4. **No new status codes:** The endpoint returns 200 for all valid requests. Invalid filter values simply return empty results.

## Verification

- `go build ./...` — passes
- `go vet ./...` — passes
- `go test ./...` — all packages pass
- `go test -race ./...` — all packages pass

## Files Modified

- `runtime/gateway/internal/approval/store.go` — Store interface + InMemoryStore implementation
- `runtime/gateway/internal/approval/file_store.go` — FileBackedStore implementation
- `runtime/gateway/internal/approval/service.go` — Service method
- `runtime/gateway/internal/handlers/approval.go` — New endpoint handler + route registration
- `runtime/gateway/internal/handlers/polish_verification_test.go` — Tests for new endpoint
- `runtime/gateway/internal/integrity/checker_test.go` — Mock update

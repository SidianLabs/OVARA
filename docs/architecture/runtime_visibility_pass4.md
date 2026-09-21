# Runtime Visibility Status Pass - Engineering Report

## Date: 2026-05-28

## Mission
Take ownership of the runtime visibility/status layer and push it to a more complete, reliable state. Resolve the approval-count issue in status testing and extend the same pass into adjacent high-confidence visibility/reporting improvements.

---

## Root Cause Analysis: The Approval-Count Test Bug

### Issue
The original `TestRuntimeStatusEndpoint` test showed `approvals.pending = 0` when expecting 2, while continuation and execution counts were correct.

### Investigation Process
1. Inspected `GET /v1/runtime/status` handler implementation - found it correctly calls `h.approvalSvc.ListPending()`
2. Inspected `approval.Service.ListPending()` - correctly delegates to `store.ListByStatus(StatusPending)`
3. Inspected `InMemoryStore.ListByStatus()` - correctly iterates and filters by status
4. Created focused isolation test to trace exact behavior

### True Root Cause
**Test bug, not a code bug.** The status endpoint was returning correct values all along.

The issue was that JSON unmarshal stores numbers as `float64` when unmarshaling into `interface{}`:
```go
var resp map[string]any
json.Unmarshal(w.Body.Bytes(), &resp)
pending := resp["approvals"].(map[string]any)["pending"].(int)  // FAILS
```

The `.(int)` type assertion fails because JSON numbers unmarshal as `float64` in Go. When the type assertion failed, the code took the `0` default int value path, causing the test to see `0` instead of the actual count.

### Fix
Use `float64` type assertions when reading JSON numbers, then convert if needed:
```go
pending, _ := approvals["pending"].(float64)  // Works correctly
```

---

## Changes Made

### 1. New Test Files

#### `runtime/gateway/internal/handlers/runtime_status_approval_test.go`
Core tests verifying status endpoint approval counting:
- `TestRuntimeStatusEndpoint_Approvals` - basic approval counting
- `TestRuntimeStatusEndpoint_Continuations` - continuation by-state counting
- `TestRuntimeStatusEndpoint_Executions` - execution breakdown counting
- `TestRuntimeStatusEndpoint_MethodNotAllowed` - POST returns 405
- `TestRuntimeStatusEndpoint_Empty` - empty state behavior

#### `runtime/gateway/internal/handlers/runtime_status_comprehensive_test.go`
Comprehensive mixed-state tests:
- `TestRuntimeStatusEndpoint_MixedState` - full mixed approval/continuation/execution state
- `TestRuntimeStatusEndpoint_NilServices` - nil service handling (no panics)
- `TestRuntimeStatusEndpoint_OnlyApprovals` - partial service wiring

#### `runtime/gateway/internal/handlers/runtime_status_structure_test.go`
Response structure validation:
- `TestRuntimeStatusEndpoint_FullResponseStructure` - all expected fields present
- `TestRuntimeStatusEndpoint_WithApprovalsAndExecutions` - real integration
- `TestRuntimeStatusEndpoint_AllApprovalStatuses` - pending/approved/denied all counted correctly

**Total: 11 new status endpoint tests**

### 2. Documentation Updates

#### `docs/architecture/runtime_support_matrix.md`
Added new "Runtime Status Endpoint" section documenting:
- `GET /v1/runtime/status` endpoint
- Full response JSON schema
- Conditional field presence based on wired services

---

## Status Endpoint Response Shape

The `GET /v1/runtime/status` endpoint returns:

```json
{
  "gateway_version": "0.8.0",
  "policy_version": "...",
  "policy_source": "in-memory",
  "gateway_id": "gw_...",
  "gateway_name": "local-gateway",
  "enrollment_state": "local",
  "maintenance_mode": false,
  "hot_reload": "disabled",
  "decision_cache_count": 0,
  "decision_cache_max": 10000,
  "receipt_count": 0,
  "approvals": {
    "pending": 0,
    "approved": 0,
    "denied": 0
  },
  "continuations": {
    "count": 0,
    "by_state": {}
  },
  "executions": {
    "total": 0,
    "succeeded": 0,
    "failed": 0,
    "running": 0,
    "timed_out": 0
  },
  "queue_paused": false,
  "queue_stats": {
    "queued": 0,
    "running": 0
  }
}
```

Fields are conditionally present:
- `approvals` - only when approval service is configured
- `continuations` - only when continuation store is configured
- `executions` - only when execution store is configured
- `queue_paused`, `queue_stats` - only when orchestrator is configured

---

## Verification

### Commands Run
```bash
cd runtime/gateway
go build ./...              # Pass
go vet ./...               # Pass (no issues)
go test ./...              # Pass
go test -race ./...        # Pass (no race conditions detected)
```

### Test Coverage
- 11 new tests for `GET /v1/runtime/status`
- All tests pass individually
- Race-sensitive tests pass
- Full test suite passes

---

## What Operators Can Now Trust

### Before This Pass
- Status endpoint existed but had incomplete test coverage
- A type assertion bug in tests caused misleading failure reports
- Docs did not mention the status endpoint

### After This Pass
1. **Approval counts are trustworthy** - verified by 3 dedicated tests covering pending/approved/denied
2. **Continuation counts by state are correct** - verified by multiple mixed-state tests
3. **Execution counts by state are accurate** - verified by tests covering all terminal states
4. **Nil service handling is safe** - verified by `TestRuntimeStatusEndpoint_NilServices`
5. **Empty state behavior is sane** - verified by dedicated empty state test
6. **Documentation exists** - `runtime_support_matrix.md` now documents the endpoint

---

## Status Endpoint Behavior Summary

| Scenario | Behavior |
|----------|----------|
| All services wired | Full response with approvals, continuations, executions, queue stats |
| Only approval service | `approvals` block present; continuations/executions absent |
| No services wired | Only gateway/policy/decision cache fields; nil-safe |
| POST to status | Returns 405 Method Not Allowed |
| Mixed approval states | Correctly counts pending, approved, denied separately |
| Mixed continuation states | Correctly counts by_state (queued, approved, etc.) |
| Mixed execution states | Correctly counts total, succeeded, failed, running, timed_out |

---

## Future Visibility/Operations Work

Potential areas for future improvement (not implemented in this pass):

1. **Time-range filters** on inspection endpoints for historical analysis
2. **Pagination/cursors** for large result sets
3. **Sorting options** on list endpoints
4. **`GET /v1/approvals/stats`** - dedicated stats endpoint for approvals (currently only via status or summary)
5. **Enhanced continuation stats** - use `CountByState()` instead of iterating `ListAll()` for large stores
6. **`is_executable`/`time_to_expiry`** fields in continuation list response
7. **Last activity timestamp** in status response for stuck-work diagnosis
8. **Compact backlog summary** for operators viewing the queue

---

## Files Modified

### New Files
- `runtime/gateway/internal/handlers/runtime_status_approval_test.go`
- `runtime/gateway/internal/handlers/runtime_status_comprehensive_test.go`
- `runtime/gateway/internal/handlers/runtime_status_structure_test.go`

### Modified Files
- `docs/architecture/runtime_support_matrix.md` (added status endpoint documentation)

---

## Conclusion

The runtime visibility/status layer is now fully tested and documented. The root cause was a test bug (incorrect type assertion for JSON numbers), not a code bug in the status endpoint. All 11 new tests pass, race tests pass, and the full test suite passes.

Operators can now confidently use `GET /v1/runtime/status` to monitor:
- Approval workflow state (pending/approved/denied counts)
- Continuation backlog (by state)
- Execution outcomes (succeeded/failed/timed_out/running)
- Queue health (paused status, queued/running counts)

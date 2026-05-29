# Runtime API/Handler Consistency Pass — Engineering Report

## Summary

A focused API consistency pass was completed across the runtime's HTTP handler layer. The goal was to make the external behavior cleaner and more predictable — consistent status codes, error payloads, validation messages, and response shapes — without breaking the runtime's working behavior.

**All tests pass (`go test ./...`, `go test -race ./...`, `go vet ./...`).**

---

## Inconsistencies Found and Fixed

### 1. Dead Code: `receipts.go` — unregistered `handlePut`

`handlePut` existed and accepted `POST /v1/receipts` but was never registered in `RegisterRoutes()`. Removed the entire function and its unused `io` import.

### 2. Route Anomaly: `capabilities.go` — trailing slash with query param

The route `GET /v1/capabilities/` (with trailing slash) was registered separately from `GET /v1/capabilities`, using a query parameter (`?id=`) instead of a path parameter. This was inconsistent with every other resource handler.

**Fixed:**
- Changed route to `GET /v1/capabilities/{id}` (path param)
- Updated `handleGet` to use `r.PathValue("id")` instead of `r.URL.Query().Get("id")`
- Updated error message to `"capability id is required"` (consistent with other handlers)

### 3. Wrong Status Code: `capabilities.go` — not-found returned 400

`handleGet` returned `JSONBadRequest` (400) when a capability was not found. Missing resources should return 404.

**Fixed:** Changed to `JSONNotFound(w, "capability not found: "+leaseID)`

### 4. Wrong Status Code: `policy.go` — history entry not-found returned 400

`handleGetHistoryEntry` and `handleRestore` returned `JSONBadRequest` when a history entry was not found.

**Fixed:** Both now return `JSONNotFound(w, "policy history entry not found: "+id)`.

### 5. State Transition Errors: `continuations.go` — 400 used where 409 is correct

Attempting to enqueue, cancel, or execute a continuation in an invalid state returned 400 (Bad Request). State conflicts should return 409 Conflict.

**Fixed:**
- `handleEnqueue`: "cannot enqueue continuation: invalid state (current=X, required=approved)" → 409
- `handleCancel`: "cannot cancel continuation: invalid state (current=X)" → 409
- `handleExecute`: "continuation not in executable state" → 409

### 6. Validation Error Prefixes: Inconsistent "invalid JSON" vs "invalid request"

Different handlers used different prefixes for the same class of error (malformed JSON):
- `runtime.go`: "invalid request: ..."
- `approval.go`: "invalid request: ..."
- `capabilities.go`: "invalid JSON: ..."
- `policy.go`: "invalid JSON: ..." (multiple times)

**Fixed:** All standardized to `"invalid request body: "+err.Error()`.

### 7. Read Error Messages: "failed to read body" vs "failed to read request body"

`approval.go` used "failed to read body" while `runtime.go` used "failed to read request body".

**Fixed:** `approval.go` now uses "failed to read request body" for consistency.

### 8. `handleResume` Error Message: "cannot resume" was vague

The error from `h.service.ResumeAction(id)` was wrapped as `"cannot resume: "+err.Error()`. Also, the continuation readiness check used an inconsistent message format.

**Fixed:**
- Continuation readiness: "continuation not ready for resume: state=X" → 409 Conflict
- Service failure: "cannot resume: ..." → "resume failed: ..."

### 9. New Helper: `JSONConflict` and `JSONUnprocessableEntity`

The existing `api/errors.go` had helpers for 400, 404, 500, and 405, but no helper for 409 (Conflict) or 422 (Unprocessable Entity). State transition errors now use `JSONConflict`.

**Added:**
```go
func JSONConflict(w http.ResponseWriter, message string)
func JSONUnprocessableEntity(w http.ResponseWriter, message string)
```

---

## Standardization Decisions

### Error Response Structure

The `ErrorResponse` struct in `api/errors.go` has three fields:
```go
type ErrorResponse struct {
    Error   string `json:"error"`
    Code    string `json:"code,omitempty"`
    Message string `json:"message,omitempty"`
}
```

`Code` and `Message` are rarely populated. The convention established is:
- `Error` field: human-readable message (always populated)
- `Code` field: machine-readable error code (not used in this pass, but `JSONErrorWithCode` exists for future use)
- `Message` field: not used

### Validation Error Format

| Situation | Format |
|-----------|--------|
| Malformed JSON | `"invalid request body: <json error>"` |
| Missing required field | `"<resource> id is required"` |
| State conflict | `"cannot <action> <resource>: invalid state (current=X)"` → 409 |
| Service error | `"<action> failed: <detail>"` |
| Not found | `"<resource> not found: <id>"` → 404 |

### HTTP Status Code Conventions

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful GET, successful mutation (no explicit status) |
| 201 | Created | `POST /v1/approval/create` |
| 202 | Accepted | `POST /v1/continuations/{id}/enqueue` |
| 400 | Bad Request | Validation errors, malformed JSON, missing required fields |
| 404 | Not Found | Resource does not exist |
| 405 | Method Not Allowed | Wrong HTTP method |
| 409 | Conflict | State conflict (invalid state transition) |
| 500 | Internal Server Error | Unexpected server-side failures |

---

## Tests Added/Updated

### New Tests

**`api/errors_test.go`:**
- `TestJSONConflict` — verifies 409 response and error message
- `TestJSONUnprocessableEntity` — verifies 422 response and error message

**`handlers/capabilities_test.go`** (new file):
- `TestCapabilitiesHandler_HandleGet_PathParam` — verifies path param works
- `TestCapabilitiesHandler_HandleGet_NotFound` — verifies 404 for missing capability
- `TestCapabilitiesHandler_HandleGet_WrongMethod` — verifies 405 for wrong method
- `TestCapabilitiesHandler_HandleList` — verifies list endpoint still works

### Updated Tests

**`handlers/continuation_test.go`:**
- `TestContinuationHandler_HandleEnqueue_NotApproved`: expects 409 (was 400)
- `TestContinuationHandler_HandleCancel_NotCancellable`: expects 409 (was 400)

**`handlers/execution_test.go`:**
- `TestContinuationHandler_Execute_DuplicateBlocked`: expects 409 (was 400)
- `TestContinuationHandler_Execute_AlreadyExecutedBlocked`: expects 409 (was 400)

**`handlers/policy_test.go`:**
- `TestPolicyHandler_GetHistoryEntry_NotFound`: expects 404 (was 400)

---

## What Clients Can Rely On

### Stable API Contracts

1. **Error format is consistent**: All error responses use `{"error": "<message>"}`. No mixed formats (plain strings, arrays, etc.).

2. **Status codes are semantically correct**:
   - 400 for validation/client errors
   - 404 for missing resources
   - 409 for state conflicts
   - 405 for wrong HTTP method

3. **Capability lookup**: `GET /v1/capabilities/{id}` with path parameter (not query parameter)

4. **Validation error messages**: `"invalid request body: <detail>"` for JSON parse failures

5. **State conflict messages**: `"cannot <action> continuation: invalid state (current=X)"` for 409 responses

### Compatibility Tradeoffs

- **Breaking change**: `GET /v1/capabilities/?id=X` (query param) no longer works. Clients must use `GET /v1/capabilities/{id}` (path param). The old route with trailing slash no longer exists.
- **Breaking change**: State transition errors (enqueue/cancel/execute in invalid state) now return **409 Conflict** instead of 400. Clients checking for 400 on these cases will need to update to check for 409.
- **Breaking change**: `GET /v1/policy/history/entry?id=X` when entry not found now returns **404** instead of 400. Same for `POST /v1/policy/restore?id=X`.

---

## Commands Run

```bash
cd runtime/gateway
go build ./...         # passed
go vet ./...           # passed
go test ./...          # passed
go test -race ./...    # passed
```

---

## Remaining Rough Edges (Not Addressed)

These are intentionally deferred as they would be breaking changes or require broader refactoring:

1. **No machine-readable error codes**: `ErrorResponse.Code` field exists but is never populated. Adding error codes would improve client-side error handling but is a bigger API change.

2. **No structured success response envelope**: Some endpoints return raw objects, others wrap in `{"field": ...}`. A consistent envelope pattern (e.g., always `{"data": ..., "metadata": {...}}`) would be cleaner but is a larger API redesign.

3. **Policy validation vs simulation error distinction**: `policy.go` uses "validation error:", "simulation error:", "invalid candidate policy:" — these are context-specific and not worth standardizing at this time.

4. **Continuation execute response**: Returns stdout/stderr which could be large. Truncation is applied but there's no size limit on the response body itself.

5. **No rate limiting or request size limits** at the handler level.

---

## Files Changed

| File | Change |
|------|--------|
| `internal/api/errors.go` | Added `JSONConflict`, `JSONUnprocessableEntity` helpers |
| `internal/api/errors_test.go` | Added tests for new helpers |
| `internal/handlers/receipts.go` | Removed dead `handlePut`, removed unused `io` import |
| `internal/handlers/capabilities.go` | Path param `{id}`, 404 for not found, standardized error prefixes |
| `internal/handlers/continuations.go` | 409 Conflict for state transitions, improved error messages |
| `internal/handlers/approval.go` | Standardized "invalid request body:" prefix, improved resume error message |
| `internal/handlers/runtime.go` | Standardized "invalid request body:" prefix |
| `internal/handlers/policy.go` | 404 for history entry not found, standardized "invalid request body:" prefix |
| `internal/handlers/continuation_test.go` | Updated to expect 409 for state conflicts |
| `internal/handlers/execution_test.go` | Updated to expect 409 for state conflicts |
| `internal/handlers/policy_test.go` | Updated to expect 404 for not-found |
| `internal/handlers/capabilities_test.go` | **New** — tests for path param, 404, method not allowed |

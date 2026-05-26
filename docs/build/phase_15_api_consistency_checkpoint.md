# Phase 15: API Consistency and Error Model Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-15-api-consistency` (from `phase-14-5-observability-verification`)
**Objective**: Audit and clean up API surface, add consistent error model, align response shapes

---

## Milestone Plan

- [ ] **Milestone A**: API surface audit
- [ ] **Milestone B**: Error response model
- [ ] **Milestone C**: Response shape consistency
- [ ] **Milestone D**: Docs and examples alignment
- [ ] **Milestone E**: Verification

---

## API Surface Audit Findings

### Endpoint Inventory

| Endpoint | Method | Response Type |
|----------|--------|---------------|
| `/health` | GET | `{status: "ok"}` |
| `/ready` | GET | `{status: "ready"}` |
| `/v1/runtime/check` | POST | DecisionResponse (object) |
| `/v1/runtime/status` | GET | map with 25 fields |
| `/v1/runtime/metrics` | GET | map with 16 fields |
| `/v1/runtime/decision/{id}` | GET | DecisionResponse (object) |
| `/v1/runtime/agent/{id}/recent` | GET | `{agent_id, receipts, count}` |
| `/v1/approval/create` | POST | ApprovalRequest |
| `/v1/approval/{id}` | GET | ApprovalRequest (object) |
| `/v1/approval/{id}/approve` | POST | ApprovalRequest |
| `/v1/approval/{id}/deny` | POST | ApprovalRequest |
| `/v1/approval/{id}/resume` | POST | ResumeResult |
| `/v1/approval/pending` | GET | `{approvals: [], count}` |
| `/v1/receipts` | GET | `{receipts: [], count}` |
| `/v1/receipts/{id}` | GET | Receipt (object) |
| `/v1/receipts/decision/{id}` | GET | `{decision_id, receipts, count}` |
| `/v1/trust/context` | GET | `{agent_id, restricted, risk_count, ...}` |
| `/v1/shield/status` | GET | `{restricted_agents: [], count}` |
| `/v1/shield/status/{agent_id}` | GET | `{agent_id, restricted, ...}` |
| `/v1/shield/restrict/{agent_id}` | POST | `{agent_id, restricted, reason}` |
| `/v1/shield/unrestrict/{agent_id}` | POST | `{agent_id, restricted}` |

### Inconsistency Findings

**1. Error responses use `http.Error` (plain text) inconsistently**:
- Most handlers use `http.Error(w, "message", status)` → sends `text/plain`
- Some wrap with `fmt.Sprintf("...: %v", err)` for detail
- No structured JSON error responses anywhere

**2. List envelopes differ**:
- Approvals: `{approvals: [...], count: N}`
- Receipts: `{receipts: [...], count: N}`
- Shield status: `{restricted_agents: [...], count: N}`
- Agent recent: `{agent_id: "...", receipts: [...], count: N}`
- Decision by decision_id: `{decision_id: "...", receipts: [...], count: N}`

**3. Single-object responses lack consistent wrapper**:
- `GET /v1/approval/{id}` → direct ApprovalRequest (no `approval` key)
- `GET /v1/receipts/{id}` → direct Receipt (no `receipt` key)
- `GET /v1/shield/status/{agent_id}` → inline object (no `shield_status` key)

**4. Metrics is flat** (intentional, but inconsistent with list pattern)

**5. Count field naming**: All consistent (`count`) but used differently:
- list responses: `count` of items
- status: `decision_cache_count`, `decision_cache_max` (specific naming)
- metrics: `total_decisions`, `avg_latency_ms` (different pattern)

**6. Agent recent endpoint** has `decisions` key when receipts store returns receipts - naming mismatch:
```go
json.NewEncoder(w).Encode(map[string]any{"decisions": []any{}, "count": 0})
```
Should probably be `{"receipts": [], "count": 0}` since it returns receipts, not decisions.

---

## Implementation Results

### Milestone B: Error Response Model

**New package**: `runtime/gateway/internal/api/`

**Files created**:
- `errors.go` — ErrorResponse struct and helper functions
- `errors_test.go` — 7 tests for error helpers

**ErrorResponse struct**:
```go
type ErrorResponse struct {
    Error   string `json:"error"`
    Code    string `json:"code,omitempty"`
    Message string `json:"message,omitempty"`
}
```

**Helper functions**:
- `JSONError(w, code, message)` — base helper
- `JSONErrorWithCode(w, code, message, code)` — with error code
- `JSONBadRequest(w, message)` — 400
- `JSONNotFound(w, message)` — 404
- `JSONInternalError(w, message)` — 500
- `JSONMethodNotAllowed(w)` — 405

**Handlers updated**:
- `approval.go` — all error responses now JSON
- `receipts.go` — all error responses now JSON
- `runtime.go` — all error responses now JSON (handleCheck, handleGetDecision, handleGetStatus, handleGetMetrics)
- `trust/handler.go` — all error responses now JSON

### Milestone C: Response Shape Consistency

**Fix**: `handleGetAgentRecentDecisions` now uses `receipts` key instead of `decisions`:
```go
// Before: {"decisions": [], "count": 0}  // wrong key - returns receipts, not decisions
// After:  {"agent_id": "...", "receipts": [], "count": 0}  // correct
```

### All Tests Pass

```
ok  ovara.runtime.gateway/internal/api       0.501s (7 tests)
ok  ovara.runtime.gateway/internal/handlers  0.869s
ok  ovara.runtime.gateway/internal/trust      1.353s
[all 16 packages pass]
```
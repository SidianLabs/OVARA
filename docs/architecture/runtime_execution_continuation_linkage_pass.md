# Runtime Execution-Continuation Linkage Pass - Engineering Report

## Date: 2026-05-28

## Mission
Close the loop between execution failure diagnosis and continuation recovery so operators can quickly answer:
- This execution failed — can I retry the linked continuation right now?
- If not, why not?

---

## Gap Analysis

### Previous State
After the execution diagnostics pass, operators could see failure category, recoverable flag, and reason for any execution. After the retry diagnostics pass, operators could see retry eligibility for continuations. However, there was no direct connection: looking at a failed execution did not tell you if its linked continuation was retryable.

### Problem Identified
Operators had to:
1. Look at a failed execution, note its `continuation_id`
2. Make a second API call to `GET /v1/continuations/{id}` to check retry eligibility
3. Manually correlate the two pieces of information

This broke the flow of triage — operators had to leave the execution context to check continuation state.

---

## Solution: Link Execution Diagnostics to Continuation Retryability

### Design Decision: Single-Item GET Only

**Chosen approach:** Enrich `GET /v1/executions/{id}` with continuation retry info.

**Rejected alternative:** Enrich `GET /v1/executions` list responses with per-item continuation retry info.

**Reasoning:**
- List enrichment would require N continuation lookups per list call, which is expensive and could degrade list performance
- The single-item GET is the primary triage path — operators drill into a specific failure to decide action
- List responses still show failure diagnostics (category, recoverable) so operators can scan and prioritize
- The pattern mirrors how continuation GET already works (continuation handler has execStore but doesn't pre-enrich list)

### Implementation Details

**1. Added continuation store to ExecutionHandler**

```go
type ExecutionHandler struct {
    store      execution.Store
    contStore  continuation.Store  // NEW
    executor   *execution.ShellExecutor
}

func (h *ExecutionHandler) SetContinuationStore(store continuation.Store) {
    h.contStore = store
}
```

**2. Wired in server startup (main.go)**

```go
execHandler.SetContinuationStore(continuationStore)
```

**3. Enriched handleGet response**

```go
response := map[string]any{
    "execution": exe,
    "failure":   failureInfo,
}

if h.contStore != nil && exe.ContinuationID != "" {
    if cont, found := h.contStore.Get(exe.ContinuationID); found {
        response["retry"] = cont.RetryInfo()
    }
}
```

**Key nil-safety behaviors:**
- If `contStore` is nil (e.g., in tests), no retry info is added — no error
- If `ContinuationID` is empty, no retry info is added — not an error, just no linked continuation
- If continuation lookup fails, no retry info is added — continuation may have been cleaned up

---

## Files Modified

### Modified Files
- `runtime/gateway/internal/handlers/execution.go` — added contStore field, SetContinuationStore method, enriched handleGet
- `runtime/gateway/cmd/server/main.go` — wired continuationStore to executionHandler
- `docs/architecture/runtime_support_matrix.md` — updated GET /v1/executions/{id} response example with retry field

### New Test Files
- (no new files — added tests to existing `execution_diagnostics_test.go`)

---

## API Changes

### `GET /v1/executions/{id}` Response Change

**Before:**
```json
{
  "execution": { ... },
  "failure": { "category": "command_failed", ... }
}
```

**After:**
```json
{
  "execution": { ... },
  "failure": { "category": "command_failed", ... },
  "retry": {
    "can_retry": true,
    "retry_limit_reached": false,
    "retries_remaining": 2,
    "status": "retryable",
    "reason": "execution completed, retry available"
  }
}
```

**Note:** `retry` is only present when:
1. `contStore` is configured (not nil)
2. `execution.ContinuationID` is non-empty
3. The continuation exists in the store

---

## Tests Added

### Handler Tests (4 tests)
- `TestExecutionHandler_HandleGet_WithLinkedContinuation_Retryable` — verifies retry info appears for linked continuation with retries remaining
- `TestExecutionHandler_HandleGet_WithLinkedContinuation_Exhausted` — verifies retry info shows exhausted state when limit reached
- `TestExecutionHandler_HandleGet_WithoutContinuationStore` — verifies nil contStore doesn't add retry field
- `TestExecutionHandler_HandleGet_WithContinuation_ContinuationNotFound` — verifies missing continuation doesn't add retry field

**Total: 4 new tests**

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
- Could see failure diagnostics on an execution
- Had to make a second API call to check if the linked continuation was retryable
- Had to manually correlate execution failure to continuation retry state

### After This Pass
1. **Single-call triage** — operators see execution failure AND continuation retry status in one response
2. **Immediate actionability** — `retry.can_retry` tells operators if retry is viable at a glance
3. **Clear exhaust detection** — `retry.status = "exhausted"` shows when retry limit is reached
4. **Retries remaining** — `retry.retries_remaining` shows how many attempts are left
5. **Graceful degradation** — executions without linked continuations or with cleaned-up continuations simply omit the `retry` field

### Example Workflow
```
1. Operator calls GET /v1/executions?state=failed
   → Sees summary.failed = 12

2. Operator drills into one: GET /v1/executions/exe_abc123
   → failure.category = "command_failed"
   → failure.recoverable = true
   → retry.can_retry = true
   → retry.status = "retryable"
   → retry.retries_remaining = 2
   → Operator calls POST /v1/continuations/cnt_xyz/retry

3. Operator drills into another failed execution:
   → failure.category = "validation_error"
   → retry.can_retry = false
   → retry.status = "exhausted"
   → Operator knows this cannot be retried — needs code fix
```

---

## Future Failure/Recovery Work

1. **List enrichment with summary** — add aggregate "retryable from failed executions" count to execution list summary (requires careful cost analysis)
2. **Bulk retry by failure category** — `POST /v1/executions/retry?category=timeout` to bulk retry all timeouts
3. **Failure correlation** — group related failures by decision_id or agent_id to identify systemic issues
4. **Auto-categorization improvements** — add more patterns for better categorization
5. **Execution history per continuation** — show all execution attempts for a continuation in the continuation response

---

## Conclusion

This pass completes the connection between execution failure diagnosis and continuation recovery. Operators can now triage a failed execution and immediately determine if retry is viable — all in a single API call. The design is nil-safe, cost-effective (only one additional store lookup on single-item GET), and follows existing patterns in the codebase.

Combined with previous passes:
- **Continuation retry diagnostics** — `GET /v1/continuations/{id}` shows retry eligibility
- **Execution failure diagnostics** — `GET /v1/executions/{id}` shows failure category and recoverability
- **Execution-continuation linkage** — `GET /v1/executions/{id}` now shows BOTH failure diagnostics AND continuation retry eligibility

This forms a complete failure triage path: scan executions → drill into failures → check retryability → take action.

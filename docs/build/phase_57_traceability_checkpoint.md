# Phase 57 Traceability — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-57-traceability`
**Parent**: `phase-56-capability-governance` (commits `8ac71da`, `fb6adf1`)
**Objective**: Multi-object traceability and execution governance

---

## 1. Repository Verification

- **Current branch**: `phase-57-traceability` (freshly created)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Parent commits reviewed**:
  - `fb6adf1` docs(build): finalize phase 56 capability governance checkpoint
  - `8ac71da` feat(capabilities): add durable lease history, governance controls, and delegation visibility

---

## 2. Cross-Object Correlation Audit (Milestone A)

### Current Links Summary

| From → To | Field | Status |
|-----------|-------|--------|
| ActionRequest → Decision | (implicit via Evaluate) | Input only |
| Decision → Receipt | decision_id on Receipt | ✓ Present |
| Decision → Continuation | decision_id on Continuation | ✓ Present |
| Decision → Approval | decision_id on ApprovalRequest | ✓ Present |
| Continuation → Approval | approval_id on Continuation | ✓ Present |
| Approval → Continuation | continuation_id NOT on Approval | ✗ Gap |
| Continuation → Execution | execution_id NOT on Continuation | ✗ Gap |
| Execution → Continuation | continuation_id on Execution | ✓ Present |
| Execution → Decision | decision_id on Execution | ✓ Present |
| Execution → Approval | approval_id on Execution | ✓ Present |
| Receipt → Continuation | continuation_id NOT on Receipt | ✗ Gap |
| Receipt → Execution | execution_id NOT on Receipt | ✗ Gap |
| Event → Decision | decision_id on Event | ✓ Present |
| Event → Approval | approval_id on Event | ✓ Present |
| Event → Continuation | continuation_id on Event | ✓ Present |
| Event → Execution | execution_id NOT on Event | ✗ Gap |
| Event → Receipt | receipt_id on Event | ✓ Present |

### Gaps Identified
1. **Event → Execution**: Event has no `execution_id` — cannot directly trace through to execution via events
2. **Approval → Continuation**: ApprovalRequest doesn't track which continuation it spawned
3. **Continuation → Execution**: Continuation doesn't store the execution_id after execution
4. **Receipt → Continuation**: Receipt doesn't store continuation_id

### What's Available for Tracing
- Events can reference decision_id, approval_id, continuation_id, receipt_id
- Receipt stores decision_id, approval_id, agent_id, capability_lease_id
- Execution stores continuation_id, decision_id, approval_id, agent_id
- Continuation stores decision_id, approval_id, agent_id

---

## 3. Implementation Plan

### Milestone B: Workflow Trace Endpoint
- [ ] Add `ListByDecision` to approval Store interface + implementations
- [ ] Add `ListByDecision` to execution Store interface + implementations
- [ ] Add `GET /v1/runtime/trace?decision_id=X` endpoint to RuntimeHandler
- [ ] Trace response: decision, receipt, continuations, approvals, executions, events
- [ ] Tests for trace endpoint

### Milestone C: Execution Governance Visibility
- [ ] Add `execution_id` to Event model
- [ ] Emit events with execution_id when executions complete
- [ ] Enrich `GET /v1/executions/{id}` with continuation and approval context
- [ ] Tests for enriched execution inspection

### Milestone D: Summary/Status Enrichment
- [ ] Add `GET /v1/runtime/summary` endpoint
- [ ] Returns: recent approvals by status, recent executions by outcome, recent revocations, lease counts
- [ ] Tests for summary endpoint

### Milestone E: Docs and Verification
- [ ] Update checkpoint
- [ ] Run tests
- [ ] Real smoke test tracing a workflow end-to-end

---

## 4. Execution Log

_(to be filled as work progresses)_

---

## 5. Files to Create/Modify

### Create
- `docs/build/phase_57_traceability_checkpoint.md` — this file

### Modify
- `runtime/gateway/internal/approval/store.go` — add ListByDecision
- `runtime/gateway/internal/approval/file_store.go` — add ListByDecision
- `runtime/gateway/internal/execution/store.go` — add ListByDecision
- `runtime/gateway/internal/events/store.go` — add ExecutionID field to Event
- `runtime/gateway/internal/handlers/runtime.go` — add trace and summary endpoints
- `runtime/gateway/cmd/server/main.go` — (may need wiring)
- `runtime/gateway/internal/handlers/execution.go` — enrich execution inspection
- `docs/developer/runtime_examples.md` — document trace and summary endpoints

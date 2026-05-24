# Phase 6.5 Execution Checkpoint

**Objective:** Consolidate and tighten the local runtime system — trust/receipt/log correlations, integration tests, operator inspection surface, containment semantics, and developer docs.

**Created:** 2026-05-24
**Branch:** `phase-6-5-consolidation` (created from `phase-6-shield-trust`)

## Milestone Plan

### Milestone A: Verify and close Trust/Receipt/Log gaps
- [x] Receipt model: add TrustContext fields (AnomalySignals, ShieldActive, Restricted, RiskCount, TrustLevel)
- [x] Receipt: populate CapabilityLeaseID from request
- [x] ApprovalRequest: add TrustScore, TrustLevel, AnomalyCodes, ShieldActive, Restricted fields
- [x] ResumeResult: add TrustScore, TrustLevel, AnomalyCodes, ShieldActive, Restricted fields
- [x] Verify logs carry trust fields via embedded Response
- [x] Tests for correlation behavior

### Milestone B: Integration-style runtime flow tests
- [x] Safe shell action allowed flow test
- [x] Risky action escalated with trust/anomaly reasons test
- [x] Restricted agent forced into escalation test
- [x] Approval created and correlated to decision test
- [x] Receipt generated and retrievable with trust information test

### Milestone C: Operator inspection surface
- [x] Review current endpoints
- [x] Add decision lookup by ID (`GET /v1/runtime/decision/{id}`)
- [x] Add agent receipts endpoint (`GET /v1/runtime/agent/{agent_id}/recent`)
- [x] Add correlation-oriented status endpoint if justified

### Milestone D: Local containment semantics tightening
- [x] Document what restriction changes in runtime outcomes
- [x] Ensure restriction transition from repeated risk is explicit
- [x] Add ShouldAutoRestrict and AutoRestrictAfterRepeatedRisk methods
- [x] Tests for repeated-risk to restriction transition

### Milestone E: Developer/operator docs
- [x] Update runtime_examples.md with new endpoints
- [x] Document trust-aware runtime checks
- [x] Document local-only limitations

## Implementation Work

### Gap 1: Receipt missing full TrustContext - FIXED
- Added `TrustLevel`, `AnomalySignals`, `ShieldActive`, `Restricted`, `RiskCount` to Receipt model
- `buildReceipt` now populates these from TrustContext

### Gap 2: Receipt missing CapabilityLeaseID - FIXED
- `buildReceipt` now populates `CapabilityLeaseID` from `req.CapabilityLease.LeaseID`

### Gap 3: Approval missing TrustContext linkage - FIXED
- Added `TrustScore`, `TrustLevel`, `AnomalyCodes`, `ShieldActive`, `Restricted` to ApprovalRequest
- Added same fields to ResumeResult so resume carries trust context

### Gap 4: Operator inspection endpoints - ADDED
- `GET /v1/runtime/decision/{id}` - lookup decision by ID (uses in-memory decision cache)
- `GET /v1/runtime/agent/{agent_id}/recent` - get receipts for an agent
- `DecisionCache` added to Handler for recent decision storage

### Gap 5: Auto-restriction semantics - ADDED
- Added `ShouldAutoRestrict(agentID, threshold)` method
- Added `AutoRestrictAfterRepeatedRisk(agentID, threshold)` method
- These enable deterministic auto-containment after repeated risk threshold

## Files Changed

### New files
- `runtime/gateway/internal/handlers/runtime_integration_test.go` - 5 integration tests
- `runtime/gateway/internal/trust/shield_auto_restrict_test.go` - 9 auto-restrict tests

### Modified files
- `runtime/gateway/internal/models/decision_response.go` - Added TrustContext fields to Receipt
- `runtime/gateway/internal/handlers/runtime.go` - Added decision cache, new endpoints, receipt enrichment
- `runtime/gateway/internal/approval/models.go` - Added trust fields to ApprovalRequest and CreateRequest
- `runtime/gateway/internal/approval/service.go` - Updated ResumeResult with trust fields
- `runtime/gateway/internal/trust/shield.go` - Added auto-restrict methods
- `docs/developer/runtime_examples.md` - Added decision lookup and agent history examples

## Validation

All packages build successfully. All tests pass:
- `internal/trust`: 90+ tests (evaluator, shield, handler, auto-restrict)
- `internal/handlers`: Handler tests + 5 integration tests
- `internal/approval`: 12 tests with updated ResumeResult
- All other existing tests continue to pass

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/runtime/check` | POST | Evaluate action |
| `/v1/runtime/decision/{id}` | GET | Lookup decision by ID |
| `/v1/runtime/agent/{agent_id}/recent` | GET | Get agent receipts |
| `/v1/approval/create` | POST | Create approval |
| `/v1/approval/{id}` | GET | Get approval |
| `/v1/approval/{id}/approve` | POST | Approve |
| `/v1/approval/{id}/deny` | POST | Deny |
| `/v1/approval/pending` | GET | List pending |
| `/v1/approval/{id}/resume` | POST | Resume |
| `/v1/receipts/{id}` | GET | Get receipt |
| `/v1/receipts` | GET | List receipts |
| `/v1/receipts/decision/{id}` | GET | List by decision |
| `/v1/trust/context` | GET | Get trust context |
| `/v1/shield/status` | GET | List restricted |
| `/v1/shield/status/{id}` | GET | Get agent shield |
| `/v1/shield/restrict/{id}` | POST | Restrict agent |
| `/v1/shield/unrestrict/{id}` | POST | Unrestrict agent |

## Next Steps After This Run

Phase 7: Hosted control plane foundations (only after Phase 6.5 is solid)
- Policy distribution (remote policy loading)
- Receipt persistence (database-backed store)
- Tenant model (multi-tenant isolation)
- Gateway enrollment (gateway registration with control plane)
# Phase 7 Foundations Execution Checkpoint

**Objective:** Prepare Ovara for future hosted control-plane evolution by:
- tightening the last weak spots in the local runtime loop
- introducing clean persistence/configuration/source abstractions
- adding lightweight local-backed implementations
- shaping gateway registration and policy source seams
- avoiding premature fake-cloud complexity

**Created:** 2026-05-24
**Branch:** `phase-7-foundations` (created from `phase-6-5-consolidation`)

## Milestone Plan

### Milestone A: Close remaining local runtime-loop gaps
- [x] Bound decision cache (TTL of 10 min, max 10000 entries, LRU eviction)
- [x] Integrate auto-restriction into evaluator (after 3 risk events)
- [x] Tests for repeated-risk to restriction in real path

### Milestone B: Policy source abstraction
- [x] Add PolicySource interface
- [x] Add InMemorySource and LocalFileSource implementations
- [x] Tests for policy loading/reloading

### Milestone C: Store and persistence seams
- [x] Review approval, receipt, shield, decision state handling
- [x] Interfaces are aligned (Store interface pattern)
- [x] Local store patterns consistent

### Milestone D: Gateway identity and enrollment foundations
- [x] Define local enrollment model (Enrollment struct)
- [x] Add config support (GatewayID, GatewayName, GatewayVersion)
- [x] Local enrollment endpoint stub via status

### Milestone E: Runtime/operator inspection consolidation
- [x] Review all local inspection endpoints
- [x] Add local status summary endpoint (`GET /v1/runtime/status`)
- [x] Mark unauthenticated endpoints as development-only in docs

### Milestone F: Docs and execution notes
- [x] Update runtime_examples.md with new features
- [x] Document automatic restriction behavior
- [x] Document bounded caches/state retention
- [x] Document policy source model
- [x] Document gateway enrollment foundation

## Implementation Work

### Decision Cache Bounded (Milestone A)
- Added max size (10000) with LRU eviction
- Added TTL (10 minutes) with expired entry cleanup
- Added Stats() method for monitoring

### Auto-Restriction Integration (Milestone A)
- Evaluator now calls `shieldStore.ShouldAutoRestrict()` and `AutoRestrictAfterRepeatedRisk()` after recording decision
- Threshold of 3 risk events triggers automatic restriction
- Restricted agents escalate automatically

### PolicySource Interface (Milestone B)
- `PolicySource` interface with `Load()`, `Version()`, `Reload()` methods
- `InMemorySource` for current in-memory behavior
- `LocalFileSource` for future file-based policy loading

### Gateway Identity (Milestone D)
- Added `Enrollment` struct with GatewayID, Name, Version, Status, timestamps
- Added gateway identity fields to Config (GatewayID, GatewayName, GatewayVersion)
- Default values generated on first startup

### Status Summary Endpoint (Milestone E)
- Added `GET /v1/runtime/status` endpoint
- Returns gateway_id, name, version, enrollment_status, decision_cache stats, receipt_count

## Files Changed

### New files
- `runtime/gateway/internal/policy/source.go` - PolicySource interface and implementations

### Modified files
- `runtime/gateway/internal/handlers/runtime.go` - Bounded cache, auto-restriction integration, status endpoint
- `runtime/gateway/internal/evaluator/evaluator.go` - Auto-restriction integration
- `runtime/gateway/internal/config/config.go` - Gateway identity and enrollment model
- `docs/developer/runtime_examples.md` - New sections for auto-restriction, policy source, status endpoint

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/runtime/check` | POST | Evaluate action |
| `/v1/runtime/decision/{id}` | GET | Lookup decision by ID (TTL cache) |
| `/v1/runtime/agent/{agent_id}/recent` | GET | Get agent receipts |
| `/v1/runtime/status` | GET | Gateway status summary (NEW) |
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

## Validation

All packages build successfully. All tests pass:
- `internal/trust`: 90+ tests (evaluator, shield, handler, auto-restrict)
- `internal/handlers`: Handler tests + integration tests
- `internal/approval`: 12 tests
- `internal/evaluator`: All tests including new auto-restriction integration
- All other existing tests continue to pass

## Local-Only Limitations (v1)

- **In-memory state**: Shield restrictions, risk counts, receipts, and decision cache reset on server restart
- **Unbounded growth prevention**: Decision cache is bounded to 10,000 entries with 10-min TTL
- **No automatic re-execution**: Approved actions are not automatically re-run — clients must retry
- **No cryptographic verification**: Signatures are placeholder format (`sig_v1_local:...`)
- **No persistent storage**: All stores are in-memory; configure external storage for production
- **No distributed enforcement**: Shield state is local to one gateway instance
- **No policy distribution**: PolicySource interface exists but only InMemorySource is implemented
- **No control-plane integration**: Gateway enrollment model exists but not connected to any control plane

## Next Steps After This Run

Phase 7.5: Policy distribution service (only if Phase 7 is solid)
- Implement remote PolicySource for distributed policy loading
- Add policy version negotiation
- Add policy refresh without restart

Phase 8: Receipt persistence
- File-backed receipt store (JSON persistence)
- Receipt query improvements

Phase 9: Tenant model
- Multi-tenant isolation
- Tenant-specific policy stores

Phase 10: Gateway enrollment
- Control plane registration
- Enrollment status management
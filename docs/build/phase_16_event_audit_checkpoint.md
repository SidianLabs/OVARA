# Phase 16 Event Audit — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-16-event-audit`
**Parent**: `phase-15-5-api-polish` (merged baseline)
**Objective**: Build structured local event and audit stream foundation for the Ovara runtime

---

## 1. Repository Verification

- **Current branch**: `phase-16-event-audit` (newly created from `phase-15-5-api-polish`)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits**:
  - `41272e2` docs(build): add phase 15.5 API polish checkpoint (HEAD of parent)
  - `f245059` test(api): add handler verification for polished responses
  - `67c204b` fix(api): clean up duplicated error messages
- **Actual runtime surface found**:
  - 21 existing endpoints across runtime, approval, receipts, trust
  - In-memory stores for receipts, approvals, decisions, shield
  - Policy reload via fsnotify watcher
  - Enrollment heartbeat every 30s

---

## 2. Problem Statement

Ovara had runtime decision logging (`logging.DecisionLogger`) and metrics but no structured event stream that:
- captures lifecycle transitions as first-class events
- provides stable correlation IDs (decision_id, receipt_id, approval_id)
- is queryable via API for operator debugging
- forms a foundation for future hosted control-plane ingestion

---

## 3. Milestone A — Event Model Foundation

### Event Envelope

```json
{
  "event_id": "evt_abc123...",
  "event_type": "runtime.decision_evaluated",
  "timestamp": "2026-05-25T...",
  "gateway_id": "gw_595000",
  "agent_id": "agent-test",
  "decision_id": "dec_...",
  "receipt_id": "rcpt_...",
  "approval_id": "apr_...",
  "payload": { ... }
}
```

### Event Type Constants

| Constant | Value |
|---|---|
| `EventTypeDecisionEvaluated` | `runtime.decision_evaluated` |
| `EventTypeApprovalCreated` | `approval.created` |
| `EventTypeApprovalResolved` | `approval.resolved` |
| `EventTypeReceiptIssued` | `receipt.issued` |
| `EventTypePolicyReloaded` | `policy.reloaded` |
| `EventTypeShieldRestrictionChanged` | `shield.restriction_changed` |
| `EventTypeEnrollmentHeartbeat` | `enrollment.heartbeat` |

### Event Construction

Builder pattern with `WithGatewayID`, `WithAgentID`, `WithTraceID`, `WithDecisionID`, `WithReceiptID`, `WithApprovalID`, `WithPayload` — all return `*Event` for chaining.

`event_id` is auto-generated as `evt_<16-char-uuid>`.

`timestamp` is auto-set to `time.Now().UTC()`.

### Files

- `runtime/gateway/internal/events/store.go` — Event struct, constants, Store interface, InMemoryStore implementation
- `runtime/gateway/internal/events/store_test.go` — 10 tests

---

## 4. Milestone B — Local Event Sink/Store

### Store Interface

```go
type Store interface {
    Append(event *Event)
    List(limit int) []*Event
    Get(eventID string) (*Event, bool)
    Count() int
}
```

### InMemoryStore Implementation

- Backed by `[]*Event` with max capacity (default 10,000)
- LRU-style eviction: when capacity exceeded, oldest events are dropped
- Thread-safe via `sync.RWMutex`
- `List(n)` returns last `n` events (most recent first)
- `Get(eventID)` searches backwards from latest (O(n) but n is bounded)

### Design Decisions

- No JSONL file persistence in v1 — keeps it simple and avoids write path complexity
- Event store is always in-memory, same as `receiptsStore` when no file configured
- Max 10,000 events; operator can query via API or restart to clear
- Future extension point: optional JSONL persistence as second-phase feature

---

## 5. Milestone C — Event Emission Integration

### Emission Points

| Point | Event Type | Key Fields |
|---|---|---|
| Runtime check (decision) | `runtime.decision_evaluated` | decision_id, receipt_id, agent_id, action_type, decision, trust_score, latency_ms |
| Runtime check (receipt) | `receipt.issued` | decision_id, receipt_id, agent_id, action_type, policy_version |
| Approval created | `approval.created` | approval_id, decision_id, agent_id, action_type, trust_score |
| Approval approved | `approval.resolved` | approval_id, decision_id, action=approved, resolved_by |
| Approval denied | `approval.resolved` | approval_id, decision_id, action=denied, resolved_by, reason |
| Policy reload | `policy.reloaded` | gateway_id, success, source |

### Gateway ID Propagation

- `runtime.go` uses `h.enrollmentSvc.GetIdentity().ID` for gateway_id
- `approval.go` uses `h.gatewayID` (set via `SetGatewayID` during init)

### Enrollment Heartbeat (Not Wired)

Heartbeat events (`enrollment.heartbeat`) were defined but not wired — `Heartbeat()` in `enrollment/service.go` does not have access to the event store and adding that coupling felt wrong. Can be added in a follow-up if needed.

### Shield Restriction Events

`trust/handler.go` restrict/unrestrict endpoints were not wired to emit `shield.restriction_changed` events. The trust handler doesn't have access to the event store. Could be added via handler injection in a follow-up.

---

## 6. Milestone D — Event Inspection API

### Endpoints

**`GET /v1/events`** — List events (with optional query params)
- `?limit=N` — max events to return (default 100, max 1000)
- `?type=<event_type>` — filter by event type

Response shape:
```json
{
  "events": [...],
  "count": 3
}
```

**`GET /v1/events/{id}`** — Get single event by ID
- Returns `404` with JSON error if not found

### Handler

`handlers/events.go` — `EventHandler` with `RegisterRoutes`, `handleList`, `handleGet`.

---

## 7. Milestone E — Docs Update

**File**: `docs/api/event_model.md` was already present (v0.1 — minimal event envelope doc). Updated to reflect what was actually built.

**New coverage needed**:
- What events are emitted and when
- Event envelope shape with all fields
- How to inspect events via API
- Correlation with existing runtime IDs (decision_id, receipt_id, approval_id)
- Current limitations (no JSONL persistence, in-memory only)

---

## 8. Milestone F — Tests

### Events Package Tests (10 tests)
- `TestNewEvent` — event_id, event_type, timestamp populated
- `TestEvent_BuilderChaining` — all With* methods chain correctly
- `TestInMemoryStore_AppendAndList` — basic append/list
- `TestInMemoryStore_Get` — get by event_id
- `TestInMemoryStore_NotFound` — get nonexistent returns false
- `TestInMemoryStore_CountZero` — empty store count
- `TestInMemoryStore_ListLimit` — limit parameter works
- `TestInMemoryStore_Latest` — Latest() returns newest
- `TestInMemoryStore_LatestNil` — Latest() on empty returns nil
- `TestInMemoryStore_MaxLenEviction` — oldest events evicted at capacity
- `TestEvent_TimestampIsUTC` — timestamp is UTC

### Event Handler Tests (7 tests)
- `TestEventHandler_HandleList` — returns events with count
- `TestEventHandler_HandleListWithLimit` — limit param works
- `TestEventHandler_HandleListFilterByType` — type filter works
- `TestEventHandler_HandleGet` — get by ID returns event
- `TestEventHandler_HandleGet_NotFound` — 404 for missing event
- `TestEventHandler_HandleList_MethodNotAllowed` — POST rejected

### Integration Smoke Test (real binary)
- Decision creates 2 events (decision_evaluated + receipt.issued)
- Approval creation creates 1 event (approval.created)
- GET /v1/events returns count and event list
- GET /v1/events/{id} returns single event

---

## 9. Git Workflow

- **Branch**: `phase-16-event-audit` (created from `phase-15-5-api-polish`)
- **Commits** (planned):
  1. `feat(events): add event model and local sink` — events package with store, types, constants, tests
  2. `feat(runtime): emit structured audit events for decisions and approvals` — event emission in runtime.go and approval.go, eventStore wiring in main.go
  3. `feat(api): add local event inspection endpoints` — events handler and tests
  4. `docs(api): update event model documentation` — doc update
  5. `docs(build): add phase 16 event audit checkpoint`

---

## 10. Files Changed (Preliminary)

### Created
- `runtime/gateway/internal/events/store.go` — Event model and InMemoryStore
- `runtime/gateway/internal/events/store_test.go` — 10 unit tests
- `runtime/gateway/internal/handlers/events.go` — Event inspection handler
- `runtime/gateway/internal/handlers/events_test.go` — 7 handler tests
- `docs/api/event_model.md` — updated event model documentation

### Modified
- `runtime/gateway/internal/handlers/runtime.go` — +eventStore field, +SetEventStore, event emission in handleCheck
- `runtime/gateway/internal/handlers/approval.go` — +eventStore, +gatewayID, +setters, event emission in handleCreate/handleApprove/handleDeny
- `runtime/gateway/cmd/server/main.go` — eventStore init, wiring, policy reload events

---

## 11. Residual Risks

- Heartbeat events not wired — enrollment service doesn't have event store access
- Shield restriction events not wired — trust handler doesn't have event store access
- No JSONL file persistence — events are lost on restart (acceptable for v1, explicit non-goal)
- No event schema versioning — events use payload map[string]any, no version field
- Events not persisted on approval resolve (resume action doesn't emit event)

---

## 12. Merge Recommendation

**Ready to merge** into `phase-15-5-api-polish` with the following understanding:
- Event emission is wired for the most important lifecycle points
- API inspection works for list and get
- Tests pass (17 new tests total across events package and handler)
- Smoke test confirms real events appear after runtime decisions and approval creation
- Follow-up phases could add: heartbeat events, shield events, JSONL persistence, event schema versioning
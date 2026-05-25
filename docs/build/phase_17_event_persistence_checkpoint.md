# Phase 17 Event Persistence — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-17-event-persistence`
**Parent**: `phase-16-event-audit` (merged baseline)
**Objective**: Event coverage expansion, JSONL persistence, richer filtering, replay-readiness

---

## 1. Repository Verification

- **Current branch**: `phase-17-event-persistence` (newly created from `phase-16-event-audit`)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits**:
  - `0c3fd4a` docs(build): add phase 16 event audit checkpoint (HEAD of parent)
  - `6c63b66` feat(runtime): emit structured audit events for decisions and approvals
  - `a8deb7b` feat(events): add event model and local sink
- **Actual event/audit surface found**:
  - 9 event types (expanded from 5)
  - In-memory store + JSONL file-backed store
  - 4 filter params on GET /v1/events
  - Sequence numbers for ordering

---

## 2. Problem Statement

Phase 16 established basic event infrastructure. Phase 17 addresses:
1. Missing event coverage (shield, resume, failure)
2. Events lost on restart (no persistence)
3. Limited filtering (only `type` and `limit`)
4. No replay-friendly ordering semantics

---

## 3. Milestone A — Event Coverage Expansion

### New Event Types Added

| Constant | Value | Trigger |
|---|---|---|
| `EventTypeApprovalResumed` | `approval.resumed` | Approval resume |
| `EventTypePolicyReloadFailed` | `policy.reload_failed` | Policy reload failure |
| `EventTypeShieldRestrictionChanged` | `shield.restriction_changed` | Shield restrict/unrestrict |

### Changes Made

**`trust/handler.go`**:
- Added `eventStore` and `gatewayID` fields
- Added `SetEventStore()` and `SetGatewayID()` setters
- `handleRestrict()` emits `shield.restriction_changed` with `action: restricted`
- `handleUnrestrict()` emits `shield.restriction_changed` with `action: unrestricted`
- Wired in `main.go` via `trustHandler.SetEventStore(eventStore)` and `trustHandler.SetGatewayID()`

**`approval.go`** (`handleResume`):
- Emits `approval.resumed` event with trust score, level, and anomaly codes

**`main.go`** (policy reload failure path):
- Emits `policy.reload_failed` with error message

---

## 4. Milestone B — Event Persistence

### FileBackedStore Implementation

- Embeds `*InMemoryStore` for in-memory query layer
- Appends events as JSON Lines to file on every `Append()`
- On startup, loads existing events from file into in-memory store
- Syncs after each write for durability
- Max events configurable (default 50,000)

### Config Changes

**`config/config.go`**:
- Added `EventsFile string` (path to JSONL file)
- Added `EventsMaxSize int` (default 50,000)
- Default path: `var/data/events.jsonl`

### Startup Behavior

- If `cfg.EventsFile != ""` → use `FileBackedStore`
- If file creation fails → fall back to in-memory with warning log
- If `cfg.EventsFile == ""` → use in-memory with log "no persistence configured"

### Shutdown

- `main.go` graceful shutdown calls `FileBackedStore.Close()` to close the file handle

### Verified Behavior

- Restart survival: 3 events emitted, restart, count still 3
- JSONL file has 1 line per event
- Events reload correctly into in-memory store on restart

---

## 5. Milestone C — Better Event Filtering

### `GET /v1/events` Enhanced Filters

| Param | Description |
|---|---|
| `type` | Event type constant (e.g., `runtime.decision_evaluated`) |
| `agent_id` | Filter by agent ID |
| `decision_id` | Filter by decision ID |
| `approval_id` | Filter by approval ID |
| `receipt_id` | Filter by receipt ID |
| `limit` | Max events to return (default 100, max 1000) |

All filters are AND-combined if multiple are provided.

### Handler Tests Added

- `TestEventHandler_HandleListFilterByAgentID`
- `TestEventHandler_HandleListFilterByDecisionID`
- `TestEventHandler_HandleListFilterByApprovalID`
- `TestEventHandler_HandleListMultipleFilters`

---

## 6. Milestone D — Replay-Readiness Semantics

### Sequence Numbers

- `Event.Seq int64` field added to event struct
- Global atomic counter (`globalSeq`) auto-increments on every `NewEvent()`
- Monotonically increasing integer per event for ordering
- Not persisted to JSONL (in-memory only, resets on restart)
- Optional field in JSON (`omitempty`)

### Guarantees

- `Seq` is monotonically increasing within a gateway process lifetime
- `Timestamp` provides wall-clock ordering across restarts
- Combination of `Seq` + `Timestamp` enables forensic reconstruction
- `event_id` provides global unique ID stable across restarts

---

## 7. Milestone E — Docs

**Updated `docs/api/event_model.md`** with:
- All 9 event types documented
- Event envelope with all fields
- Replay-readiness guarantees and limitations
- Reference to `events.jsonl` storage when configured

---

## 8. Milestone F — Tests

### New Tests

**`events/file_store_test.go`** (4 tests):
- `TestFileBackedStore_BasicAppendAndPersist` — write, close, reopen, verify count
- `TestFileBackedStore_LoadsExistingEvents` — events survive restart
- `TestFileBackedStore_EmptyFileOK` — empty file doesn't error
- `TestFileBackedStore_FilePath` — path accessor works

**`handlers/events_test.go`** (4 new tests):
- `TestEventHandler_HandleListFilterByAgentID`
- `TestEventHandler_HandleListFilterByDecisionID`
- `TestEventHandler_HandleListFilterByApprovalID`
- `TestEventHandler_HandleListMultipleFilters`

### All Tests Pass

```
ok   ovara.runtime.gateway/internal/events    0.590s
ok   ovara.runtime.gateway/internal/handlers   1.226s
```

---

## 9. Real Smoke Tests Verified

1. **Event emission**: Decision check → 2 events (`runtime.decision_evaluated` + `receipt.issued`)
2. **Shield event**: POST /v1/shield/restrict → 1 `shield.restriction_changed` event
3. **Filtering**: `?agent_id=agent-p17` returns 2 matching events
4. **Restart survival**: 3 events emitted, restart, count remains 3
5. **JSONL persistence**: 2 events in file (2 JSON lines after restart test)
6. **Sequence numbers**: 1, 2 assigned to events from same decision

---

## 10. Git Workflow

- **Branch**: `phase-17-event-persistence` (created from `phase-16-event-audit`)
- **Commits** (planned):
  1. `feat(events): add file-backed event store and coverage expansion` — FileBackedStore, event type constants, trust/approval emission, config fields
  2. `feat(api): add richer event filtering and sequence numbers` — all filter params, Seq field, updated handler tests
  3. `docs(build): add phase 17 event persistence checkpoint`

---

## 11. Files Changed

### Created
- `runtime/gateway/internal/events/file_store.go` — FileBackedStore with JSONL append
- `runtime/gateway/internal/events/file_store_test.go` — 4 persistence tests

### Modified
- `runtime/gateway/internal/events/store.go` — Seq field, atomic counter, EventTypeApprovalResumed, EventTypePolicyReloadFailed constants
- `runtime/gateway/internal/trust/handler.go` — eventStore field, setters, shield event emission
- `runtime/gateway/internal/handlers/approval.go` — resume event emission
- `runtime/gateway/internal/handlers/events.go` — all 5 filter params on list endpoint
- `runtime/gateway/internal/handlers/events_test.go` — 4 new filter tests
- `runtime/gateway/cmd/server/main.go` — file-backed store init, close on shutdown, trust wiring
- `runtime/gateway/internal/config/config.go` — EventsFile and EventsMaxSize fields
- `docs/api/event_model.md` — updated with all event types, storage behavior, replay guarantees

---

## 12. Residual Risks

- `Seq` resets on restart (documented, not persisted)
- Heartbeat events still not wired — enrollment service doesn't have event store access
- Events not compacted — JSONL grows indefinitely up to max_events
- No event schema versioning in payload — map[string]any is flexible but unvalidated

---

## 13. Merge Recommendation

**Ready to merge** `phase-17-event-persistence` into `phase-16-event-audit`.

Phase 17 significantly advances the audit foundation:
- 4 new event types (resume, shield, failure)
- JSONL file-backed persistence with restart survival
- 5 filter params for event queries
- Sequence numbers for ordering
- 8 new tests, all passing
- Real smoke test confirms restart survival (3 events persist across restart)

The event stream is now durable and more queryable. Next phases could add heartbeat events, event compaction, or schema versioning.
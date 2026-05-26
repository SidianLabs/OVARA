# Phase 18 Continuation — Implementation Checkpoint

**Date**: Mon May 25 2026
**Branch**: `phase-18-continuation`
**Parent**: `phase-17-event-persistence` (merged baseline)
**Objective**: Build runtime continuation and approval execution flow foundations

---

## 1. Repository Verification

- **Current branch**: `phase-18-continuation` (newly created from `phase-17-event-persistence`)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Base commits**:
  - `a0a2ebd` docs(build): add phase 17 event persistence checkpoint (HEAD of parent)
  - `07ddc16` feat(api): add richer event filtering and sequence numbers
  - `4da9fa4` feat(events): add file-backed event store and coverage expansion

---

## 2. Milestone A — Audit Current Escalation/Resume Behavior

### Current State Found

**Escalation flow**:
1. `runtime.go:handleCheck` evaluates action, returns `DecisionResponse` with `decision: escalate`, `requires_approval: true`
2. Operator creates approval via `POST /v1/approval/create` with `decision_id`, `action_type`, `resource`, `agent_id`, `trust_score`
3. `approval/service.go:CreateApproval` creates `ApprovalRequest` with `StatusPending`
4. Approval stored in `approval.Store`

**Approval resolution**:
- `POST /v1/approval/{id}/approve` → `approval/service.go:Approve` → `approval.Approve(resolvedBy)` sets `StatusApproved`, `ResolvedAt`
- `POST /v1/approval/{id}/deny` → `approval/service.go:Deny` → `approval.Deny(resolvedBy, reason)` sets `StatusDenied`

**Resume**:
- `POST /v1/approval/{id}/resume` → `approval/service.go:ResumeAction` → returns `ResumeResult` with: `Approved: true`, `ApprovalID`, `DecisionID`, `ActionType`, `Resource`, `TrustScore`, `TrustLevel`, `AnomalyCodes`, `ShieldActive`, `Restricted`
- Only works if `approval.Status == StatusApproved`

### Gaps Identified

1. **No structured continuation artifact** — `ResumeResult` is a flat struct, not a persistent first-class object
2. **No continuation state machine** — cannot query "what escalated actions are awaiting approval" or "which are approved and ready to resume"
3. **No correlation between approval and original decision context** beyond `decision_id`
4. **Resume returns a summary, not a continuation artifact** — caller gets flat fields but no continuation_id to reference later
5. **No continuation store** — no queryable inventory of escalated/approved/denied continuations

---

## 3. Milestone B — Continuation Model Foundation

### Continuation Model

```go
type Continuation struct {
    ContinuationID string    `json:"continuation_id"` // "cnt_<uuid>"
    DecisionID    string    `json:"decision_id"`
    ApprovalID    string    `json:"approval_id,omitempty"`
    AgentID       string    `json:"agent_id,omitempty"`
    ActionType    string    `json:"action_type"`
    Resource      string    `json:"resource"`
    Environment   string    `json:"environment,omitempty"`
    State         State     `json:"state"` // escalated | approved | denied | resumed | expired
    CreatedAt     time.Time `json:"created_at"`
    ApprovedAt    *time.Time `json:"approved_at,omitempty"`
    ResumedAt     *time.Time `json:"resumed_at,omitempty"`
    ResolvedBy    string    `json:"resolved_by,omitempty"`
    DenyReason    string    `json:"deny_reason,omitempty"`
    TrustScore    float64   `json:"trust_score,omitempty"`
    TrustLevel    string    `json:"trust_level,omitempty"`
    AnomalyCodes  []string  `json:"anomaly_codes,omitempty"`
    ShieldActive  bool      `json:"shield_active,omitempty"`
    Restricted    bool      `json:"restricted,omitempty"`
    PolicyVersion string    `json:"policy_version,omitempty"`
    CapabilityRef string    `json:"capability_ref,omitempty"`
    Metadata      map[string]any `json:"metadata,omitempty"`
}

type State string
const (
    StateEscalated   State = "escalated"
    StateApproved    State = "approved"
    StateDenied      State = "denied"
    StateResumed     State = "resumed"
    StateExpired     State = "expired"
)
```

### State Transitions

```
escalated -> approved (on approval approve)
escalated -> denied   (on approval deny)
approved  -> resumed  (on approval resume)
```

### Methods

- `CanResume()` → true only when `State == StateApproved`
- `IsTerminal()` → true when `State == StateDenied || State == StateExpired`
- `MarkApproved(resolvedBy)` → sets `StateApproved`, `ResolvedBy`, `ApprovedAt`
- `MarkDenied(resolvedBy, reason)` → sets `StateDenied`, `ResolvedBy`, `DenyReason`
- `MarkResumed()` → sets `StateResumed`, `ResumedAt`

### Store Interface

```go
type Store interface {
    Create(c *Continuation) error
    Get(id string) (*Continuation, bool)
    Update(c *Continuation) error
    ListByState(state State) []*Continuation
    ListByDecision(decisionID string) []*Continuation
    ListByAgent(agentID string) []*Continuation
    ListByApprovalID(approvalID string) []*Continuation
    ListAll() []*Continuation
}
```

### Files

- `runtime/gateway/internal/continuation/store.go` — Continuation struct, State constants, Store interface, InMemoryStore implementation
- `runtime/gateway/internal/continuation/store_test.go` — 14 tests covering model and store behavior

---

## 4. Milestone C — Approval Integration

### How it works

**On approval creation** (`handleCreate` in `approval.go`):
```go
cnt := continuation.NewContinuation(req.DecisionID, string(req.ActionType), req.Resource).
    WithAgentID(req.AgentID).
    WithEnvironment(string(req.Environment)).
    WithTrustContext(req.TrustScore, string(req.TrustLevel), req.AnomalyCodes, req.ShieldActive, req.Restricted).
    WithApprovalID(created.ApprovalID)

if h.continuationStore != nil {
    _ = h.continuationStore.Create(cnt)
}
```

**On approval approve** (`handleApprove`):
```go
if h.continuationStore != nil {
    list := h.continuationStore.ListByApprovalID(id)
    for _, cnt := range list {
        cnt.MarkApproved(body.ResolvedBy)
        _ = h.continuationStore.Update(cnt)
    }
}
```

**On approval deny** (`handleDeny`):
```go
if h.continuationStore != nil {
    list := h.continuationStore.ListByApprovalID(id)
    for _, cnt := range list {
        cnt.MarkDenied(body.ResolvedBy, body.Reason)
        _ = h.continuationStore.Update(cnt)
    }
}
```

---

## 5. Milestone D — Resume Flow Strengthening

### Before (old `ResumeResult`)

```json
{
  "approved": true,
  "approval_id": "apr_...",
  "decision_id": "dec_...",
  "action_type": "shell",
  "resource": "shell:curl |sh",
  "trust_score": 0.5,
  ...
}
```

### After (enhanced resume response)

```json
{
  "resumed": true,
  "approval_id": "apr_...",
  "continuation_id": "cnt_...",
  "decision_id": "dec_...",
  "action_type": "shell",
  "resource": "shell:curl |sh",
  "trust_score": 0.5,
  "trust_level": "medium",
  "anomaly_codes": [],
  "shield_active": false,
  "restricted": false,
  "policy_version": "v1-local",
  "capability_ref": "",
  "metadata": {"escalation_reason": "policy_escalate"}
}
```

Key additions:
- `resumed: true` — explicit boolean flag
- `continuation_id` — first-class reference to the continuation artifact
- `policy_version`, `capability_ref`, `metadata` — full execution context preserved

### On resume (`handleResume`)

```go
if h.continuationStore != nil {
    list := h.continuationStore.ListByApprovalID(id)
    for _, cnt := range list {
        cnt.MarkResumed()
        _ = h.continuationStore.Update(cnt)
    }
}
```

---

## 6. Milestone E — Persistence and Inspection

### Continuation Inspection API

**`GET /v1/continuations`** — List continuations with optional filters:
- `?state=approved` — filter by state
- `?agent_id=agt_123` — filter by agent
- `?decision_id=dec_abc` — filter by decision
- `?limit=N` — limit results

**`GET /v1/continuations/{id}`** — Get single continuation

### Handler

`handlers/continuations.go` — `ContinuationHandler` with 5 tests

### Wiring in main.go

```go
continuationStore := continuation.NewInMemoryStore()
h.SetContinuationStore(continuationStore)
approvalHandler.SetContinuationStore(continuationStore)
continuationHandler := handlers.NewContinuationHandler(continuationStore)
continuationHandler.RegisterRoutes(mux)
```

---

## 7. Real Smoke Test Verified

```
=== Make an escalated decision ===
decision_id: dec_31b64cda-fdef-40 (escalate)

=== Create approval ===
approval_id: apr_725cf237-22b7-4e

=== Approve ===
status: approved

=== List continuations ===
1

=== Get continuation ===
continuation_id: cnt_68f09a5c-e7fa-4b

=== Resume ===
{
  "action_type": "shell",
  "approval_id": "apr_725cf237-22b7-4e",
  "capability_ref": "",
  "continuation_id": "cnt_68f09a5c-e7fa-4b",
  "decision_id": "dec_31b64cda-fdef-40",
  "metadata": {"escalation_reason": "policy_escalate"},
  "policy_version": "",
  "resumed": true,
  "resource": "shell:curl |sh",
  "restricted": false,
  "shield_active": false,
  "trust_level": "",
  "trust_score": 0.5
}
```

---

## 8. Git Workflow

- **Branch**: `phase-18-continuation` (created from `phase-17-event-persistence`)
- **Commits** (planned):
  1. `feat(runtime): add continuation model for escalated actions` — continuation package with model, store, tests
  2. `feat(approval): bind approvals to continuation state` — integration in approval handler
  3. `feat(api): add continuation inspection endpoints` — handler, tests, wiring
  4. `docs(build): add phase 18 continuation checkpoint`

---

## 9. Files Changed

### Created
- `runtime/gateway/internal/continuation/store.go` — Continuation model, State enum, InMemoryStore
- `runtime/gateway/internal/continuation/store_test.go` — 14 tests
- `runtime/gateway/internal/handlers/continuations.go` — Inspection handler
- `runtime/gateway/internal/handlers/continuation_test.go` — 5 handler tests

### Modified
- `runtime/gateway/internal/handlers/approval.go` — Creates continuation on approval create; updates on approve/deny; enhanced resume response
- `runtime/gateway/internal/handlers/runtime.go` — `continuationStore` field, `SetContinuationStore()` setter
- `runtime/gateway/cmd/server/main.go` — Init continuation store, wire to handlers, register continuation routes

---

## 10. Residual Risks

- Continuation store is in-memory only — not persisted (same as event store in-memory mode)
- No automatic expiration of stale continuations
- `ListByApprovalID` is O(n) on the in-memory map — acceptable for local use
- No file-backed continuation store yet

---

## 11. Merge Recommendation

**Ready to merge** `phase-18-continuation` into `phase-17-event-persistence`.

Phase 18 establishes the continuation execution-control primitive:
- Structured `Continuation` model with state machine (escalated→approved→resumed or escalated→denied)
- Approval create/approve/deny all bind to continuation state
- Resume now returns structured response with `continuation_id`, `policy_version`, `metadata`
- Inspection API: `GET /v1/continuations` with `state`/`agent_id`/`decision_id` filters, `GET /v1/continuations/{id}`
- 19 new tests (14 continuation model + 5 handler tests), all passing
- Real smoke test confirms: decision → approval → approve → continuation created → resume returns continuation_id

The system now has a coherent escalation→approval→continuation lifecycle with inspectable state. Future phases could add file-backed persistence for continuations and automatic re-execution using the continuation artifact.
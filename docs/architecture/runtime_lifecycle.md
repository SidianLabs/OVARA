# Runtime Lifecycle

How a request flows through the Ovara Runtime Gateway from action intent to execution outcome.

For a quick reference of supported action types and resource formats, see [runtime_support_matrix](runtime_support_matrix.md).

For troubleshooting, see the [Runtime Troubleshooting Guide](../../runtime/gateway/TROUBLESHOOTING.md).

---

## Lifecycle Stages

```
Action Request
     │
     ▼
┌─────────────────────────────────────┐
│  1. Request Validation              │
│     Validate action_type, resource, │
│     environment, identity fields     │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  2. Identity Verification           │
│     Validate AgentIdentity          │
│     (issuer, subject_id validity)    │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  3. Capability Validation           │
│     If CapabilityLease provided:    │
│     - Not revoked                   │
│     - Not expired                   │
│     - Action in allowed_actions     │
│     - Resource within scope         │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  4. Policy Evaluation              │
│     Match rules by action_type     │
│     and environment                │
│     deny > escalate > allow          │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  5. Trust Evaluation               │
│     Score + anomaly detection      │
│     - Risky shell patterns         │
│     - Production targeting          │
│     - Repeated risk events          │
│     Can override to escalate        │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  6. Decision                        │
│     allow / deny / escalate         │
│     + reason_codes + trust_score    │
└─────────────────┬───────────────────┘
                  │
        ┌─────────┼─────────┐
        │         │         │
     allow     deny    escalate
        │         │         │
        ▼         ▼         ▼
    Executed   Receipt   Approval
   (target)   issued   workflow
                          │
                          ▼
                    ┌───────────┐
                    │ Approve/  │
                    │ Deny       │
                    └─────┬─────┘
                          │ approved
                          ▼
                    Continuation
                    created
                          │
                          ▼
                    Orchestrator
                    pickup
                          │
                          ▼
                    Executor
                    routing
                          │
                          ▼
                    Execution
                    record
                          │
                          ▼
                    Terminal
                    state
```

---

## Stage 1: Request Validation

The gateway validates the incoming `ActionRequest` fields:

- `action_type` — required; must match a registered executor action type
- `resource` — required; format checked by the specific executor
- `environment` — required; must be `local`, `dev`, `staging`, or `production`
- `agent_identity` — optional; if provided, validated for issuer and subject format

**Validation failure** → returns `deny` with `reason_code=action_not_allowed`

---

## Stage 2: Identity Verification

If `agent_identity` is provided, the gateway validates:

- `issuer` is present and valid format
- `subject_id` is present and valid format

**Identity failure** → returns `deny` with `reason_code=identity_invalid`

---

## Stage 3: Capability Validation

If `capability_lease` is provided, the gateway validates:

1. **Revocation check** — lease ID is not in the revocation list
2. **Expiry check** — lease has not expired
3. **Action check** — `action_type` is in `allowed_actions`
4. **Scope check** — `resource` matches the `resource_scope` pattern

**Capability failure** → returns `deny` with:
- `capability_revoked` — lease was revoked
- `capability_expired` — lease past expiry
- `capability_not_allowed` — action not in lease
- `capability_scope_mismatch` — resource not in lease scope

---

## Stage 4: Policy Evaluation

The gateway matches rules from the active policy file against:
- `action_type` of the request
- `environment` of the request

**Rule priority:**
1. `deny` rules — block immediately (trumps all)
2. `allow` rules — permit if no deny
3. `escalate` rules — block pending approval (if no allow)
4. Default — `allow` if nothing matches (implicit)

**Matching:**
- `action_type="*"` matches any action
- `environment="*"` matches any environment
- Specific rules (`shell`, `dev`) override wildcards (`*`, `*`)

---

## Stage 5: Trust Evaluation

The trust evaluator independently analyzes the request and can override the policy decision:

**Anomaly signals:**
- `risky_shell_pattern` — resource contains a dangerous pattern (e.g. `curl |sh`, `rm -rf`)
- `production_target` — resource or environment targets production
- `repeated_risk` — agent has had multiple escalate/deny decisions

**Trust levels:** `high` (>0.8), `medium` (0.5–0.8), `low` (<0.5)

If trust score is low or anomalies detected, the decision can be upgraded from `allow` → `escalate`.

---

## Stage 6: Decision

The gateway returns a `DecisionResponse`:

| Decision | Meaning |
|----------|---------|
| `allow` | Execute immediately; interceptor proceeds with the action |
| `deny` | Block; no execution; denial receipt is issued |
| `escalate` | Block; create an approval to proceed |

Each decision includes:
- `decision_id` — opaque ID for this decision
- `reason_codes[]` — why this decision was made
- `trust_score` — computed trust score (0.0–1.0)
- `requires_approval` — boolean; true if escalate
- `receipt_stub` — partial receipt for the decision

---

## Escalate → Approval Flow

When the decision is `escalate`, the action is blocked. To proceed:

```
1. POST /v1/approval/create
   → Creates approval in "pending" state

2. Human reviews and POST /v1/approval/{id}/approve
   → Approval transitions to "approved"

3. POST /v1/approval/{id}/resume
   → A continuation is created in "escalated" state
   → Orchestrator picks it up and transitions to "approved" → "queued" → "ready"
   → Executor runs the action
   → Execution record is created with terminal state (succeeded/failed/timed_out)
```

If denied at step 2: continuation goes to `denied` state and is never executed.

## Approval Inspection Endpoints

To view and filter approval requests:

```
GET /v1/approval/pending
   → Returns all pending approval requests

GET /v1/approvals
   → Returns all approvals with optional filters:
   ?status=pending|approved|denied
   ?requester=<decision_id>
   ?environment=local|dev|staging|production
   ?action_type=shell|exec|git.push|git.pull|git.fetch|git.checkout
   ?limit=N (max 1000, default 100)
```

Both endpoints return:
```json
{
  "approvals": [...],
  "count": N
}
```

---

## Continuation Inspection Endpoints

```
GET /v1/continuations
   → Returns all continuations with optional filters:
   ?state=escalated|approved|queued|ready|executed|failed|timed_out|denied|expired|cancelled|resumed
   ?agent_id=<agent_id>
   ?decision_id=<decision_id>
   ?approval_id=<approval_id>
   ?action_type=shell|exec|git.push|git.pull|git.fetch|git.checkout
   ?environment=local|dev|staging|production
   ?limit=N (max 1000, default 100)

GET /v1/continuations/{id}
   → Returns a single continuation

GET /v1/continuations/stats
   → Returns aggregate counts by state and queue status

GET /v1/continuations/queue
   → Returns queued continuations ready for pickup (scheduling view)
```

Primary filters (mutually exclusive): `state`, `agent_id`, `decision_id`.
Secondary filters (composable, applied after primary): `approval_id`, `action_type`, `environment`.

Response shape:
```json
{
  "continuations": [...],
  "count": N,
  "executable": M
}
```

---

## Execution Inspection Endpoints

```
GET /v1/executions
   → Returns all executions with optional filters:
   ?state=succeeded|failed|timed_out|pending|running
   ?continuation_id=<continuation_id>
   ?decision_id=<decision_id>
   ?action_type=shell|exec|git.push|git.pull|git.fetch|git.checkout
   ?limit=N (max 1000, default 100)

GET /v1/executions/{id}
   → Returns a single execution record

GET /v1/executions/stats
   → Returns aggregate counts by state and persistence metadata
```

Primary filters (mutually exclusive): `continuation_id`, `state`, `decision_id`.
Secondary filters (composable): `action_type`.

Response shape:
```json
{
  "executions": [...],
  "count": N
}
```

---

## Continuation State Machine

```
escalated
    │
    │ resume (after approval)
    ▼
approved
    │
    │ orchestrator pickup
    ▼
queued ─────────────────────────────────┐
    │                                   │
    │ orchestrator assigns              │
    ▼                                   │
ready ──────────────────────────────────┤
    │                                   │
    │ executor runs                     │
    ▼                                   │
executed (succeeded / failed / timed_out)
    │
    │ POST /v1/continuations/{id}/retry
    ▼ (if retry_count < max_retries)
resumed
    │
    │ orchestrator pickup
    ▼
ready
```

**Terminal states:** `denied`, `expired`, `cancelled`, `executed` (after success)

**Other transitions:**
- `escalated` → `denied` — human denies at approval step
- `escalated` → `expired` — continuation past expiry time
- `escalated` → `cancelled` — explicit cancel via API
- `executed` (failed/timeout) → `resumed` — `POST /v1/continuations/{id}/retry` (if retry_count < max_retries)
- `resumed` → `resumed` — retry again (increments retry_count)

---

## Orchestrator Pickup Loop

The orchestrator polls the continuation store every 2 seconds (configurable):

1. Lists all continuations in `queued` state
2. For each `queued` continuation:
   - Checks the executor registry for a matching action type
   - If found: transitions to `ready` and executes
   - If not found: logs `SKIP no executor registered` and leaves it queued

**Pausing:** The orchestrator can be paused (`POST /v1/continuations/queue/pause`). When paused, it stops picking up new continuations but continues running.

---

## Executor Routing

The `ExecutorRegistry` maps action types to executors at startup:

```
shell            → ShellExecutor     (system shell /bin/sh -c)
exec             → DirectExecutor    (direct subprocess, no shell)
git.push         → GitExecutor       (git push)
git.pull         → GitExecutor       (git pull)
git.fetch        → GitExecutor       (git fetch)
git.checkout     → GitExecutor       (git checkout)
github.push      → GitHubExecutor     (GitHub API push)
github.pr        → GitHubExecutor     (GitHub API pull request)
github.merge     → GitHubExecutor     (GitHub API merge)
github.delete_branch → GitHubExecutor (GitHub API delete branch)
ci.trigger       → CIExecutor        (CI/CD workflow trigger)
shell.sandboxed  → SandboxExecutor   (Docker-sandboxed shell, opt-in)
```

The shell executor passes the command through the system shell, supporting all shell features (pipes, redirects, environment variables, globbing).

The direct executor (`exec:`) runs the binary directly, splitting on spaces. No shell interpretation — pipes and redirects do not work.

The git executor runs git operations in the specified repository path using `git -C <repo>`.

The GitHub executor uses the GitHub API with a token from config (`github_token`). If no token is configured, the executor logs a warning and actions are skipped at runtime.

The CI executor triggers workflows via GitHub Actions or a generic webhook URL (configured via `ci_token` / `ci_webhook_url`). If not configured, actions are skipped.

The sandbox executor wraps the shell executor and runs commands inside a Docker container, providing isolation. Enabled via `OVARA_SANDBOX_ENABLED=true`.

---

## Background Services

### Execution Sweeper
- Runs every 5 minutes (configurable)
- Calls `FileBackedStore.Sweep()` which marks stale executions as removable
- Logs `SWEEP execution removed=N` when cleanup runs

### Continuation Sweeper
- Runs every 60 seconds (configurable)
- Scans non-terminal continuations for expiry
- Transitions expired continuations to `expired` state
- Logs `SWEEP continuations scanned=N expired=N`

### Reconciliation on Startup
- Both sweepers run once on gateway startup
- Scans for continuations that were `escalated` or `approved` but past their expiry time
- Transitions them to `expired`

### Decision Cache Cleanup
- Runs every 5 minutes (configurable)
- Evicts old entries from the in-memory decision cache
- Prevents unbounded memory growth from repeated requests

---

## Event Emission

Major lifecycle events are written to the event store (file-backed JSONL by default):

- `execution.started` — execution record created
- `execution.succeeded` / `execution.failed` / `execution.timed_out` — terminal outcome
- `continuation.created` — continuation created from approval
- `continuation.expired` — continuation expired without execution
- `continuation.sweep_completed` — sweep cycle completed
- `approval.created` / `approval.resolved` — approval state changes

Events are queryable via `GET /v1/events` and used for audit/integrity checks.

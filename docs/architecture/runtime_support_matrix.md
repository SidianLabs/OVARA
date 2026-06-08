# Runtime Support Matrix

Quick reference for what the Ovara Runtime Gateway V1 supports and how it behaves.

**Last updated:** V1 RTM
**Gateway port:** 8080 (default)

---

## Operator Authentication

The gateway supports optional, local-first bearer-token auth for operator API access,
enforced by a single middleware wrapping all routes. See
[runtime_auth.md](runtime_auth.md) for full detail.

| Config | JSON key | Default | Effect |
|--------|----------|---------|--------|
| `AuthEnabled` | `auth_enabled` | `false` | Master switch |
| `OperatorTokens` | `operator_tokens` | `[]` | Accepted `Bearer` tokens |

- When `auth_enabled=true` with tokens configured, all endpoints require
  `Authorization: Bearer <token>` except `/health`, `/ready`, and `/v1/runtime/status`.
- Tokens are compared in constant time and never logged.
- `auth_enabled=false` (default) runs open; `auth_enabled=true` with no tokens runs open
  with a loud startup warning (treated as misconfiguration).
- Errors: `401` with a JSON `{"error":...}` body for missing/invalid/empty tokens.

---

## Supported Action Types

| Action Type | Executor | Resource Format | Behavior |
|-------------|----------|-----------------|----------|
| `shell` | `ShellExecutor` (system shell) | `shell:<command>` e.g. `shell:curl http://example.com` | Policy-evaluated; allow/deny/escalate |
| `exec` | `DirectExecutor` (no shell) | `exec:<binary> [args]` e.g. `exec:curl http://example.com` | Policy-evaluated; allow/deny/escalate |
| `git.push` | `GitExecutor` | `git:<repo>[:branch]` e.g. `git:origin/main` | Policy-evaluated; allow/deny/escalate |
| `git.pull` | `GitExecutor` | `git:<repo>[:branch]` e.g. `git:origin/main` | Policy-evaluated; allow/deny/escalate |
| `git.fetch` | `GitExecutor` | `git:<remote>[:<refspec>]` e.g. `git:origin` or `git:origin:refs/heads/main` | Policy-evaluated; allow/deny/escalate |
| `git.checkout` | `GitExecutor` | `git:<repo>:<branch>` e.g. `git:/home/user/repo:main` | Policy-evaluated; allow/deny/escalate |

### Resource Formats

**`shell:<command>`**
- Full shell command after `shell:` prefix
- Interpreted by the system shell (`/bin/sh -c`)
- Examples: `shell:ls -la`, `shell:git push origin main`

**`exec:<binary> [args]`**
- Direct subprocess, no shell interpretation
- Binary name followed by space-separated arguments
- Examples: `exec:ls`, `exec:curl http://example.com`
- Note: pipes and redirects (`|`, `>`, `&&`) do not work in `exec:` — use `shell:` for shell features

**`git:<repo>[:branch]`**
- `git:` prefix, then `repo` (required) and optional `branch` separated by `:`
- The repo is used as a path for `git -C <repo>` operations
- The branch is used as the target ref for push/pull
- Examples: `git:origin/main`, `git:/home/user/repo`, `git:/home/user/repo:feature-branch`

---

## Environments

| Environment | Valid Values |
|-------------|--------------|
| `local` | `local` — developer workstation |
| `dev` | `dev` — development environment |
| `staging` | `staging` — pre-production |
| `production` | `production` — production |

The environment is passed in the `environment` field of the action request and used in policy rule matching.

---

## Default Policy Behavior (`sample_policy_local.json`)

| Action | Environment | Default Outcome | Reason |
|--------|-------------|-----------------|--------|
| `shell` | `local` | **allow** | Safe for local dev |
| `shell` | `dev` | **escalate** | Risky; requires human review |
| `shell` | `production` | **deny** | Too risky to auto-approve |
| `shell` with risky pattern | `dev` | **escalate** | Pattern match triggers escalation |
| `exec` | `*` | **escalate** | Direct subprocess always requires approval |
| `git.pull` | `*` | **allow** | Read-only operation |
| `git.fetch` | `*` | **allow** | Read-only operation |
| `git.checkout` | `*` | **escalate** | Modifies working tree — requires approval |
| `git.push` | `*` | **escalate** | Modifies remote state |
| `*` (catch-all) | `production` | **escalate** | Requires explicit approval |

### Risky Shell Patterns (always escalate)

These patterns in a `shell:` resource trigger trust-based escalation even in `dev`:

- `curl |sh` / `wget |sh` — remote code execution
- `rm -rf` — destructive file removal
- `mkfs` — filesystem destruction
- `dd if=` — raw disk write
- `:(){:|:&};:` — fork bomb
- `chmod -R 777` / `chown -R` — permission escalation
- `sudo su` / `passwd root` — privilege escalation
- `killall` / `pkill -9` / `reboot` / `shutdown` — service disruption
- `> /etc/` / `> /var/` — system file write
- `/dev/sd*` — raw device write
- `nc -e` / `bash -i` — network shell

---

## Decision Outcomes

| Decision | Meaning | What happens |
|----------|---------|--------------|
| `allow` | Action is permitted | Interceptor executes the command |
| `deny` | Action is blocked | Command does not run; denial receipt is issued |
| `escalate` | Action blocked pending approval | Command does not run; create an approval to proceed |

---

## Approval Workflow States

| Status | Meaning |
|--------|---------|
| `pending` | Awaiting human review |
| `approved` | Human approved; action can be resumed |
| `denied` | Human denied; action is permanently blocked |

Approval → create → approve → resume is the escalation flow:

```
escalate decision → POST /v1/approval/create → pending → POST /v1/approval/{id}/approve → approved → POST /v1/approval/{id}/resume → execution
```

### List Endpoint Ordering Contract

All operator list endpoints (`GET /v1/approvals`, `GET /v1/continuations`, `GET /v1/executions`) share a common ordering and limiting contract:

- Results are returned in a **deterministic** order. The default is newest first (by creation time for approvals/continuations, by start time for executions), with the item ID as a stable tiebreaker for equal timestamps.
- `sort=oldest` reverses the order to oldest first; `sort=newest` is the explicit form of the default.
- Sorting is applied **after** all filters and **before** `limit`, so the default `limit` window returns the most recent N items reproducibly rather than an arbitrary subset.
- `GET /v1/continuations/queue` is ordered FIFO (oldest `queued_at` first) to reflect scheduling order.

> Note: earlier builds returned list items in Go map-iteration order, which made `limit` return a non-reproducible subset. The deterministic contract above replaces that behavior.

### Approval Inspection Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v1/approval/pending` | List all pending approvals |
| `GET /v1/approvals` | List all approvals with optional filters |


**`GET /v1/approvals` filters:**
- `status` — `pending`, `approved`, or `denied`
- `requester` — Filter by decision ID (escalation requester)
- `environment` — `local`, `dev`, `staging`, or `production`
- `action_type` — `shell`, `exec`, `git.push`, `git.pull`, `git.fetch`, or `git.checkout`
- `created_before` — RFC3339 timestamp; include items created before this time
- `created_after` — RFC3339 timestamp; include items created after this time
- `sort` — `oldest` or `newest` by creation time; default is `newest` (most recent first)
- `limit` — Max results (1–1000, default 100). Applied after filtering and sorting, so the default window returns the most recent `limit` items deterministically.

### Continuation Inspection Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v1/continuations` | List all continuations with optional filters |
| `GET /v1/continuations/{id}` | Get a single continuation with retry diagnostics |
| `GET /v1/continuations/stats` | Aggregate counts by state |
| `GET /v1/continuations/queue` | List queued continuations (scheduling view) |

**`GET /v1/continuations` filters:**
- Primary (mutually exclusive): `state`, `agent_id`, `decision_id`
- Secondary (composable): `approval_id`, `environment`, `action_type`, `retryable`, `created_before`, `created_after`, `sort`, `after`
- `created_before` — RFC3339 timestamp; include items created before this time
- `created_after` — RFC3339 timestamp; include items created after this time
- `sort` — `oldest` or `newest` by creation time; default is `newest` (most recent first)
- `limit` — Max results (1–1000, default 100). Applied after filtering and sorting, so the default window returns the most recent `limit` items deterministically.
- `after` — Cursor for pagination; value is a base64-encoded string from a prior response's `next_cursor` field. When provided, returns only items that appear after the cursor position in the sorted order, allowing stable pagination through large result sets.

**Pagination:**
List results are sorted deterministically (newest first by default, or oldest first with `sort=oldest`). When `limit` is applied and more items exist, the response includes a `next_cursor` field encoding the timestamp and ID of the last returned item. Pass this value as the `after` parameter to fetch the next page. When no `next_cursor` is present, all available items have been returned.

**`retryable` filter values:**
- `retryable=true` — only continuations that can be retried (executed or resumed with retries remaining)
- `retryable=false` — only continuations that cannot be retried (exhausted, terminal, pending approval, etc.)

**Example:** `GET /v1/continuations?state=executed&retryable=true` returns failed/timeout continuations that are still retryable.

**Age filtering examples:**
- `GET /v1/continuations?retryable=true&created_before=2026-05-25T00:00:00Z` — retryable items created before a specific date
- `GET /v1/continuations?created_after=2026-05-27T00:00:00Z&sort=oldest` — items created after a date, oldest first
- `GET /v1/approvals?status=pending&created_before=2026-05-20T00:00:00Z` — stale pending approvals before a cutoff

**`GET /v1/continuations` response:**
```json
{
  "continuations": [...],
  "count": 10,
  "executable": 2,
  "retryable": 3,
  "next_cursor": "MjAyNi0wNS0yOVQxNDozODo0Ni4xNzY0NDVaOmNudF9hYmMxMjM="
}
```

The `next_cursor` field is only present when `limit` was applied and additional items exist. Its value is a base64-encoded string containing the timestamp and ID of the last returned item, suitable for passing as the `after` parameter to fetch subsequent pages.

**`GET /v1/continuations/{id}` response:**
```json
{
  "continuation": {
    "continuation_id": "cnt_abc123",
    "state": "executed",
    "retry_count": 1,
    "max_retries": 3,
    ...
  },
  "retry": {
    "can_retry": true,
    "retry_limit_reached": false,
    "retries_remaining": 2,
    "status": "retryable",
    "reason": "execution completed, retry available"
  }
}
```

**Retry status values:**
- `retryable` — continuation can be retried
- `exhausted` — retry limit reached
- `disabled` — max_retries is 0
- `terminal` — continuation is in terminal state (denied/expired/cancelled)
- `not_needed` — continuation has not been executed yet
- `pending_approval` — continuation awaiting approval
- `unknown` — unexpected state

### Continuation Action Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/continuations/{id}/enqueue` | Enqueue an approved continuation for execution |
| `POST /v1/continuations/{id}/cancel` | Cancel a queued, ready, or resumed continuation |
| `POST /v1/continuations/{id}/retry` | Retry a failed or completed continuation |
| `POST /v1/continuations/{id}/execute` | Execute a continuation directly (bypasses orchestrator) |
| `POST /v1/continuations/recover-executing` | Force-recover all continuations stuck in `executing` to `executed` |
| `POST /v1/continuations/{id}/recover-executing` | Force-recover a single continuation from `executing` to `executed` |
| `POST /v1/continuations/queue/pause` | Pause the execution queue |
| `POST /v1/continuations/queue/resume` | Resume the execution queue |

**`POST /v1/continuations/{id}/retry`:**
- Transitions continuation from `executed` or `resumed` state to `resumed`
- Increments `retry_count`
- Allowed when `retry_count < max_retries` (default max_retries = 3)
- Returns 409 Conflict if:
  - State is not `executed` or `resumed`
  - `max_retries` is 0
  - `retry_count >= max_retries`

**`POST /v1/continuations/recover-executing`:**
- Atomically transitions every continuation currently in `StateExecuting` to `StateExecuted`, making them retryable
- Intended for live recovery of hung executions where the executor is stuck but the gateway is still running
- The orchestrator's startup sweep handles post-crash recovery; this endpoint handles runtime recovery
- Supports `?dry_run=true` to enumerate candidates without mutating state
- Supports `?older_than_minutes=N` to only recover items that have been in `executing` for longer than N minutes; useful for targeting genuinely stuck work without catching items that are still young
- Each successfully recovered item emits a `continuation.recovered_executing` event
- Response shape:
  ```json
  {
    "scanned": 3,
    "recovered": 3,
    "skipped": 0,
    "dry_run": false,
    "items": [
      {
        "continuation_id": "cnt_abc123",
        "action_type": "shell",
        "age_seconds": 612,
        "state": "executed"
      }
    ]
  }
  ```
- `scanned` is the number of items in `executing` at the time of the call
- `recovered` is the number actually transitioned (items that finished concurrently are counted as `skipped`)
- `items[].age_seconds` is how long each item had been in `executing` (measured from `created_at`)

**`POST /v1/continuations/{id}/recover-executing`:**
- Transitions a single continuation from `StateExecuting` to `StateExecuted`, making it retryable
- Returns 404 if the continuation is not found
- Returns 409 Conflict if the continuation is not in `StateExecuting`
- Emits a `continuation.recovered_executing` event on success
- Response shape:
  ```json
  {
    "continuation_id": "cnt_abc123",
    "state": "executed",
    "message": "continuation recovered from executing for retry"
  }
  ```

### Execution Inspection Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /v1/executions` | List all executions with optional filters |
| `GET /v1/executions/{id}` | Get a single execution record |
| `GET /v1/executions/stats` | Aggregate counts by state and persistence info |

**`GET /v1/executions` filters:**
- Primary (mutually exclusive): `continuation_id`, `state`, `decision_id`
- Secondary (composable): `action_type`, `after`
- `sort` — `oldest` or `newest` by execution start time; default is `newest` (most recently started first)
- `limit` — Max results (1–1000, default 100). Applied after filtering and sorting, so the default window returns the most recent `limit` executions deterministically.
- `after` — Cursor for pagination; value is a base64-encoded string from a prior response's `next_cursor` field. When provided, returns only items that appear after the cursor position in the sorted order.

**Pagination:**
List results are sorted deterministically (newest first by default, or oldest first with `sort=oldest`). When `limit` is applied and more items exist, the response includes a `next_cursor` field encoding the `StartedAt` timestamp and `ExecutionID` of the last returned item. Pass this value as the `after` parameter to fetch the next page.

**`GET /v1/executions` response:**
```json
{
  "executions": [...],
  "count": 10,
  "summary": {
    "total": 100,
    "succeeded": 80,
    "failed": 15,
    "running": 3,
    "timed_out": 2
  },
  "next_cursor": "MjAyNi0wNS0yOVQxNDozODo0Ni4xNzY0NDVaOmV4ZV9hYmMxMjM="
}
```

The `next_cursor` field is only present when `limit` was applied and additional items exist. Its value is a base64-encoded string containing the timestamp and ID of the last returned item, suitable for passing as the `after` parameter to fetch subsequent pages.

**`GET /v1/executions/{id}` response:**
```json
{
  "execution": {
    "execution_id": "exe_abc123",
    "state": "failed",
    "exit_code": 1,
    "error": "exit status 1",
    ...
  },
  "failure": {
    "category": "command_failed",
    "recoverable": true,
    "exit_code": 1,
    "reason": "exit status 1"
  },
  "retry": {
    "can_retry": true,
    "retry_limit_reached": false,
    "retries_remaining": 2,
    "status": "retryable",
    "reason": "execution completed, retry available"
  }
}
```

Note: `retry` is only present when the execution has a linked continuation (`continuation_id` field). If the continuation does not exist or the execution has no linked continuation, the `retry` field is omitted.

**Failure categories:**
- `success` — execution completed successfully (exit code 0)
- `in_progress` — execution is currently running
- `timeout` — execution exceeded its timeout threshold
- `command_failed` — command exited with non-zero code
- `validation_error` — input validation failed (not recoverable)
- `not_found` — referenced file, path, or resource not found
- `permission_denied` — permission denied error (not recoverable)
- `executor_error` — executor-specific error (e.g., binary not found)
- `git_error` — git operation error (e.g., repository not found)
- `unknown` — unrecognized error

**Recoverable errors** (`recoverable: true`): `timeout`, `command_failed`, `git_error` when not about permissions
**Non-recoverable errors** (`recoverable: false`): `validation_error`, `permission_denied`, `executor_error` for "not found", `git_error` for "not found"

### Runtime Status Endpoint

| Endpoint | Description |
|----------|-------------|
| `GET /v1/runtime/status` | Aggregate runtime health and queue status |

Returns a snapshot of runtime state including approval counts, continuation counts by state, execution counts by state, and queue status:

```json
{
  "gateway_version": "0.8.0",
  "policy_version": "...",
  "policy_source": "in-memory",
  "gateway_id": "gw_...",
  "gateway_name": "local-gateway",
  "enrollment_state": "local",
  "maintenance_mode": false,
  "hot_reload": "disabled",
  "decision_cache_count": 0,
  "decision_cache_max": 10000,
  "receipt_count": 0,
  "approvals": {
    "pending": 0,
    "approved": 0,
    "denied": 0,
    "oldest_pending_at": "2026-05-28T10:30:00Z"
  },
  "continuations": {
    "count": 0,
    "by_state": {},
    "executable": 0,
    "retryable": 0,
    "oldest_executable_at": "2026-05-28T12:00:00Z",
    "oldest_retryable_at": "2026-05-28T11:00:00Z"
  },
  "executions": {
    "total": 0,
    "succeeded": 0,
    "failed": 0,
    "running": 0,
    "timed_out": 0
  },
  "queue_paused": false,
  "queue_stats": {
    "queued": 0,
    "running": 0
  }
}
```

Fields are conditionally present based on what services are wired into the handler:
- `approvals` — only when approval service is configured
- `continuations` — only when continuation store is configured
- `executions` — only when execution store is configured
- `queue_paused`, `queue_stats` — only when orchestrator is configured

**Continuation summary fields:**
- `executable` — continuations in `approved`, `queued`, or `ready` state, ready to be picked up by the orchestrator
- `retryable` — continuations in `executed` or `resumed` state with `retry_count < max_retries`, eligible for retry
- `executing` — continuations currently in `executing` state (claimed and actively running); informational, not actionable via enqueue/retry/cancel
- `oldest_executable_at` — RFC3339 timestamp of the oldest executable continuation (omitted if no executable continuations)
- `oldest_retryable_at` — RFC3339 timestamp of the oldest retryable continuation (omitted if no retryable continuations)
- `oldest_executing_at` — RFC3339 timestamp of the oldest currently-executing continuation (omitted if no executing continuations)

**Top-level executing observability:**
When the orchestrator is configured, the status response also includes:
- `executing` — top-level count of continuations in `executing` state (mirrors `continuations.executing` for convenience at the root)
- `oldest_executing_at` — only present at the root when there is at least one executing continuation

Stuck-executing detection should combine the `executing` count, `oldest_executing_at`, and the `executing_breaching` SLA breach count (below) to determine whether live operator recovery is needed.

**Approval summary fields:**
- `oldest_pending_at` — RFC3339 timestamp of the oldest pending approval (omitted if no pending approvals)

### SLA Health Diagnostics

The runtime tracks SLA health via configurable thresholds and exposes breach counts in two endpoints:

#### Config fields

| Config | JSON key | Default | Description |
|--------|----------|---------|-------------|
| `SLAApprovalMaxAgeMin` | `sla_approval_max_age_min` | `30` | Max age (minutes) for pending approvals before breaching |
| `SLARetryableMaxAgeMin` | `sla_retryable_max_age_min` | `60` | Max age (minutes) for retryable continuations before breaching |
| `SLAPendingApprovalMaxAgeMin` | `sla_pending_approval_max_age_min` | `30` | Alias for `SLAApprovalMaxAgeMin` |
| `SLAExecutingMaxAgeMin` | `sla_executing_max_age_min` | `5` | Max age (minutes) for a continuation in `executing` state before breaching. `executing` is normally a short-lived transient claim; values above the threshold indicate hung executions. |
| `SLAThresholds` | `sla_thresholds` | `{}` | Per-environment or per-action_type override map (future) |
| `StuckExecutingSweepIntervalSec` | `stuck_executing_sweep_interval_secs` | `0` | Interval (seconds) for the periodic stuck-executing recovery sweep. `0` disables automatic recovery. When enabled, the sweep runs on this interval and recovers continuations in `executing` state older than `stuck_executing_recovery_threshold_min`. |
| `StuckExecutingRecoveryThresholdMin` | `stuck_executing_recovery_threshold_min` | `30` | Minimum age (minutes) for a continuation in `executing` state before the periodic sweep will recover it. Must be significantly larger than `sla_executing_max_age_min` to avoid false positives. Only effective when `stuck_executing_sweep_interval_secs > 0`. |

#### GET /v1/runtime/status — `sla` section

When the gateway config has SLA thresholds configured (or defaults are in effect), `GET /v1/runtime/status` includes an `sla` object:

```json
{
  "sla": {
    "approvals_breaching": 2,
    "retryable_breaching": 1,
    "executing_breaching": 1,
    "approval_threshold_min": 30,
    "retryable_threshold_min": 60,
    "executing_threshold_min": 5
  }
}
```

- `approvals_breaching` — count of pending approvals older than `sla_approval_max_age_min`
- `retryable_breaching` — count of retryable continuations (executed/resumed with retries remaining) older than `sla_retryable_max_age_min`
- `executing_breaching` — count of continuations in `executing` state older than `sla_executing_max_age_min`
- `approval_threshold_min` — effective approval threshold in minutes
- `retryable_threshold_min` — effective retryable threshold in minutes
- `executing_threshold_min` — effective executing threshold in minutes

#### GET /v1/runtime/health — focused health view

A lightweight health endpoint for load balancers and orchestrators:

```json
{
  "healthy": true,
  "sla": {
    "approvals_breaching": 0,
    "retryable_breaching": 0,
    "approval_threshold_min": 30,
    "retryable_threshold_min": 60
  }
}
```

`healthy` is `false` when:
- `maintenance_mode` is active (with `reason: "maintenance_mode"`)
- Note: SLA breaches are surfaced in the `sla` object but do **not** by themselves set `healthy=false` — they are informational; it is the operator's responsibility to interpret breach counts.

**Why `GET /v1/runtime/health` and not extending `status`?**

`/v1/runtime/status` is already a large aggregate snapshot (policy version, cache stats, per-store persistence info, queue stats). Adding per-breaching counts there layers the data on top of the existing age signals, keeping breach data near the data it relates to. `/v1/runtime/health` is a purpose-built, minimal endpoint suitable for `HEAD`/`GET` from load balancers without pulling the full aggregate dump. This follows the "least-overlapping" principle: health is a single boolean + small sla object; status is a full diagnostic snapshot.

---

## Continuation States

A continuation represents an action in-flight after an `escalate` decision.

| State | Meaning |
|-------|---------|
| `escalated` | Created from escalate decision; waiting for approval |
| `approved` | Human approved; ready for execution |
| `queued` | Enqueued for execution by the orchestrator |
| `ready` | Orchestrator has picked it up |
| `executing` | Claimed and actively running; never a resting state. On gateway restart, orphaned executing continuations are swept to `executed` for operator recovery via retry. Operators can also force-recover via `POST /v1/continuations/recover-executing` if a live execution hangs. |
| `executed` | Execution completed (success, timeout, or failure) |
| `denied` | Human denied |
| `expired` | Past expiry time without execution |
| `cancelled` | Explicitly cancelled |
| `resumed` | Retry after failure/timeout |

---

## Execution Terminal States

| State | Meaning |
|-------|---------|
| `succeeded` | Command completed with exit code 0 |
| `failed` | Command exited with non-zero code or error |
| `timed_out` | Command exceeded its timeout |
| `pending` | Not yet started (pre-execution) |
| `running` | Currently executing |

---

## Common Failure Modes

| Symptom | Likely Cause | Where to Look |
|---------|-------------|---------------|
| `no executor registered for action_type` | Action type has no executor; check `action_types` registered in startup logs | Startup log line: `action_types=[shell, exec, git.push, git.pull, git.fetch, git.checkout]` |
| `invalid resource: does not start with shell:` | Resource format is wrong; missing `shell:` prefix | Check the interceptor or client constructing the request |
| `exec: binary name is empty` | `exec:` resource has no binary after the prefix | Resource should be `exec:ls` not `exec:` |
| `git resource is empty` | Resource missing repo after `git:` prefix | Resource should be `git:origin/main` not `git:` |
| `continuation not in executable state` | Trying to execute a continuation not in `approved`, `queued`, or `resumed` state | Check current state via `GET /v1/continuations/{id}` |
| `approval not approved` | Calling resume on a non-approved approval | Approval must be `approved` status before resume |
| `gateway timeout: context deadline exceeded` | Gateway did not respond within the HTTP client timeout | Check gateway process is running; check gateway logs |
| Decision is `deny` but no reason given | Policy denied the action silently | Check policy rules for matching deny rule; check `reason_codes` in response |
| Continuations stuck in `executing` after restart | Gateway crashed mid-execution leaving continuations in claimed state | Orchestrator sweeps them on startup — check `RECOVER stuck-executing` log lines; stuck items become executed and retryable |
| Continuations stuck in `executing` while gateway is running | Executor hung mid-execution (live, not crash) | Use `POST /v1/continuations/recover-executing` to force-recover; check `RECOVER executing` log lines; `executing_breaching` SLA count will be > 0 above `sla_executing_max_age_min`. If `stuck_executing_sweep_interval_secs` is configured, the periodic sweep will auto-recover items older than `stuck_executing_recovery_threshold_min`. |

---

## Automatic Stuck Executing Recovery

The gateway has two mechanisms for recovering continuations stuck in `StateExecuting`:

### Startup Sweep

On every gateway startup, the orchestrator runs `sweepStuckExecuting()` which unconditionally transitions **all** continuations in `StateExecuting` to `StateExecuted`. This handles the case where a previous gateway process crashed mid-execution, leaving continuations in the claimed state. Since the previous process is no longer running, those continuations are orphaned and safe to recover.

Startup sweep is always enabled and runs once at startup before the queue poll loop begins.

### Periodic Sweep (Optional)

For long-running gateways, a periodic sweep can be enabled to automatically recover continuations that become stuck during operation (e.g., due to a hung executor). This sweep is **disabled by default** and must be explicitly configured:

```json
{
  "stuck_executing_sweep_interval_secs": 600,
  "stuck_executing_recovery_threshold_min": 30
}
```

- `stuck_executing_sweep_interval_secs=600` — sweep runs every 10 minutes
- `stuck_executing_recovery_threshold_min=30` — only recover items that have been in `executing` for > 30 minutes

**Why a separate threshold from SLA?**
- `sla_executing_max_age_min` (default: 5 min) is a *detection* threshold for the SLA breach counter — it flags items that might be stuck so the operator can investigate
- `stuck_executing_recovery_threshold_min` (default: 30 min) is a *recovery* threshold — it is intentionally much higher to avoid recovering items that are still legitimately in-flight but slow

**Design caution:** The periodic sweep is conservative by design. A slow but valid execution (e.g., a long-running git push) should not be auto-recovered. Only items that have been stuck for a very long time (well above the SLA threshold) are auto-recovered.

**Log output:**
- `RECOVER stale-executing continuation_id=cnt_abc123 action_type=shell age=45m0s — marked executed for retry` — per-item recovery
- `RECOVER stale-executing sweep completed recovered=N threshold=30m0s` — sweep summary (only when `recovered > 0`)

**If the periodic sweep is disabled** (default), operators must manually recover stuck items using:
- `POST /v1/continuations/recover-executing` — bulk recovery with optional `?older_than_minutes=N`
- `POST /v1/continuations/{id}/recover-executing` — per-item recovery

---

## Unimplemented / Aspirational Action Types

These appear in docs/policies but are **not yet implemented** in V1:

| Action Type | Status |
|------------|--------|
| `github.*` (push, pr, merge, delete_branch) | Not implemented — no GitHub API executor |
| `ci.*` (deploy, build_trigger, approval) | Not implemented — no CI system executor |
| `git.force_push` | Registered in policy but not as an executor — falls through to `SKIP no executor` |

Using an unimplemented action type in a policy is harmless (it simply never matches a registered executor). However, using it in a continuation will result in `SKIP no executor registered` at execution time.

---

## Log Prefixes

| Prefix | Component | Example |
|--------|-----------|---------|
| `EXEC pickup` | Orchestrator | `EXEC pickup action_type=shell continuation_id=cnt_abc123 resource="shell:ls"` |
| `EXEC completed=success` | Orchestrator | `EXEC completed=success action_type=shell continuation_id=cnt_abc123 execution_id=exe_xyz exit_code=0` |
| `EXEC completed=timeout` | Orchestrator | `EXEC completed=timeout action_type=shell continuation_id=cnt_abc123 timeout_s=60` |
| `EXEC completed=failed` | Orchestrator | `EXEC completed=failed action_type=shell continuation_id=cnt_abc123 exit_code=1 error="exit status 1"` |
| `SKIP no executor` | Orchestrator | `SKIP no executor registered for action_type=git.push continuation_id=cnt_abc123` |
| `APPROVAL created` | Approval service | `APPROVAL created approval_id=apr_abc123 decision_id=dec_xyz action_type=shell agent_id=agt_1 environment=dev` |
| `APPROVAL approved` | Approval service | `APPROVAL approved approval_id=apr_abc123 resolved_by=admin@example.com action_type=shell decision_id=dec_xyz` |
| `APPROVAL denied` | Approval service | `APPROVAL denied approval_id=apr_abc123 resolved_by=admin@example.com reason="too risky" action_type=shell` |
| `APPROVAL resumed` | Approval service | `APPROVAL resumed approval_id=apr_abc123 decision_id=dec_xyz action_type=shell` |
| `QUEUE enqueue` | Continuation handler | `QUEUE enqueue continuation_id=cnt_abc123 decision_id=dec_xyz action_type=shell agent_id=agt_1 state=queued` |
| `QUEUE cancel` | Continuation handler | `QUEUE cancel continuation_id=cnt_abc123 decision_id=dec_xyz action_type=shell agent_id=agt_1 state=cancelled` |
| `QUEUE pause` | Continuation handler | `QUEUE pause` |
| `QUEUE resume` | Continuation handler | `QUEUE resume` |
| `SWEEP` | Sweepers | `SWEEP continuations scanned=50 expired=3` or `SWEEP execution removed=12` |
| `RECOVER stuck-executing` | Orchestrator (startup sweep) | `RECOVER stuck-executing continuation_id=cnt_abc123 action_type=shell — marked executed for retry` |
| `RECOVER stale-executing` | Orchestrator (periodic sweep) | `RECOVER stale-executing continuation_id=cnt_abc123 action_type=shell age=45m0s — marked executed for retry` (per-item) or `RECOVER stale-executing sweep completed recovered=N threshold=30m0s` (summary) |
| `RECOVER executing` | Operator recovery endpoint / orchestrator | `RECOVER executing dry_run=false scanned=3 recovered=3 skipped=0` (endpoint) or `RECOVER executing continuation_id=cnt_abc123 action_type=shell — marked executed for retry` (per-item) |

Decision logs are written to `var/log/decisions.jsonl` (or configured path) as JSON lines, separate from stdout/stderr operational logs.

---

## Key Files and Paths

| Path | Purpose |
|------|---------|
| `cmd/server/main.go` | Gateway entry point |
| `internal/execution/store.go` | Executors: Shell, Direct, Git |
| `internal/evaluator/evaluator.go` | Policy evaluation logic |
| `internal/continuation/orchestrator.go` | Execution queue and pickup |
| `internal/continuation/store.go` | Continuation state machine |
| `internal/approval/service.go` | Approval workflow |
| `internal/policy/store.go` | Policy rule storage |
| `internal/trust/evaluator.go` | Trust scoring and anomaly detection |
| `internal/events/file_store.go` | Event persistence |
| `internal/handlers/runtime.go` | HTTP API handlers |
| `etc/config.json` | Gateway configuration |
| `examples/sample_policy.json` | Example production policy |
| `examples/sample_policy_local.json` | Example local dev policy |
| `var/data/enrollment.json` | Gateway identity |

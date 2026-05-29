# Runtime Support Matrix

Quick reference for what the Ovara Runtime Gateway V1 supports and how it behaves.

**Last updated:** V1 RTM
**Gateway port:** 8080 (default)

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
- `oldest_executable_at` — RFC3339 timestamp of the oldest executable continuation (omitted if no executable continuations)
- `oldest_retryable_at` — RFC3339 timestamp of the oldest retryable continuation (omitted if no retryable continuations)

**Approval summary fields:**
- `oldest_pending_at` — RFC3339 timestamp of the oldest pending approval (omitted if no pending approvals)

---

## Continuation States

A continuation represents an action in-flight after an `escalate` decision.

| State | Meaning |
|-------|---------|
| `escalated` | Created from escalate decision; waiting for approval |
| `approved` | Human approved; ready for execution |
| `queued` | Enqueued for execution by the orchestrator |
| `ready` | Orchestrator has picked it up |
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

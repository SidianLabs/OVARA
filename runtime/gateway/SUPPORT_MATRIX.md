# Runtime Gateway V1 Support Matrix

Quick reference for what the gateway supports and how it behaves.

**See also:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for diagnosing issues.

---

## Supported Action Types

| Action Type | Executor | Resource Format | Example |
|------------|----------|----------------|---------|
| `shell` | ShellExecutor (system shell) | `shell:<command>` | `shell:curl http://example.com` |
| `exec` | DirectExecutor (no shell) | `exec:<binary> [args]` | `exec:curl http://example.com` |
| `git.push` | GitExecutor | `git:<repo>[:branch]` | `git:origin/main` |
| `git.pull` | GitExecutor | `git:<repo>[:branch]` | `git:/home/user/repo:feature` |
| `git.fetch` | GitExecutor | `git:<remote>[:<refspec>]` | `git:origin` or `git:origin:refs/heads/main` |
| `git.checkout` | GitExecutor | `git:<repo>:<branch>` | `git:/home/user/repo:main` or `git:/home/user/repo:feature-branch` |

### Key Differences: `shell` vs `exec`

| Feature | `shell:` | `exec:` |
|---------|----------|---------|
| Pipes (`\|`) | ✓ Supported | ✗ Not supported |
| Redirects (`>`, `>>`) | ✓ Supported | ✗ Not supported |
| Globbing (`*`) | ✓ Supported | ✗ Not supported |
| Shell built-ins | ✓ Supported | ✗ Not supported |
| Environment variables | ✓ Supported | Only via explicit args |

Use `exec:` when you need to run a binary without shell interpretation (security-relevant). Use `shell:` when you need shell features.

---

## Environments

Valid values: `local`, `dev`, `staging`, `production`

The environment is passed in the `environment` field of the action request and matched against policy rules.

---

## Default Policy (`sample_policy_local.json`)

| Action | Environment | Outcome | Notes |
|--------|------------|---------|-------|
| `shell` | `local` | **allow** | Safe for development |
| `shell` | `dev` | **escalate** | Risky; requires human review |
| `shell` | `production` | **deny** | Too risky to auto-approve |
| `shell` + risky pattern | `dev` | **escalate** | Trust evaluator overrides |
| `exec` | `*` | **escalate** | Direct subprocess always requires approval |
| `git.pull` | `*` | **allow** | Read-only operation |
| `git.fetch` | `*` | **allow** | Read-only operation |
| `git.checkout` | `*` | **escalate** | Modifies working tree — requires approval |
| `git.push` | `*` | **escalate** | Modifies remote state |
| `*` (catch-all) | `production` | **escalate** | Requires explicit approval |

---

## Decision Outcomes

| Decision | Meaning |
|----------|--------|
| `allow` | Execute immediately |
| `deny` | Block; no execution |
| `escalate` | Block; requires approval workflow |

---

## Approval States

| Status | Meaning |
|--------|---------|
| `pending` | Awaiting human review |
| `approved` | Approved; can resume |
| `denied` | Permanently blocked |

---

## Continuation States

| State | Meaning |
|-------|---------|
| `escalated` | Created from escalate; awaiting approval |
| `approved` | Human approved |
| `queued` | Enqueued for execution |
| `ready` | Orchestrator picked up (via atomic claim) |
| `executed` | Execution completed |
| `denied` | Human denied |
| `expired` | Past expiry time |
| `cancelled` | Explicitly cancelled |
| `resumed` | Retry after failure |

---

## Execution Claim Model

The gateway uses atomic claiming to prevent duplicate executions when multiple paths (orchestrator, HTTP endpoint) race on the same continuation.

### Claim Methods

| Method | Valid Source States | Target State | Use Case |
|--------|---------------------|--------------|----------|
| `ClaimForExecution` | `queued`, `resumed` | `ready` | First-run execution pickup |
| `ClaimForRetry` | `resumed` | `ready` | Retry-path execution pickup |

### State Transitions

```
First-run (Queued):
  Queued -> ClaimForExecution -> Ready -> Executed
First-run (Approved via HTTP):
  Approved -> (MarkReady) -> Ready -> Executed

Retry:
  Executed -> Retry() -> Resumed -> ClaimForRetry -> Ready -> Executed
```

### Atomicity Guarantees

- `ClaimForExecution` and `ClaimForRetry` are atomic under the store's lock
- Only ONE caller wins; all others receive `false` / a 409 Conflict response
- The store-level race test (`TestInMemoryStore_ClaimForExecution_RaceProof_OnlyOneWins`) verifies that with 10 concurrent claimers on the same continuation ID, exactly 1 wins
- Integration-level tests verify the same guarantee at the handler level

### Race Path: Orchestrator vs HTTP Endpoint

Both paths (`POST /v1/continuations/{id}/execute` and `Orchestrator.executeOne`) may race on the same continuation:

1. First to call `ClaimForExecution` wins and proceeds
2. Loser receives 409 Conflict (HTTP) or no-op (orchestrator re-poll)
3. Exactly one execution record is created

---

## Execution Terminal States

| State | Meaning |
|-------|---------|
| `succeeded` | Exit code 0 |
| `failed` | Non-zero exit or error |
| `timed_out` | Exceeded timeout |

---

## Common Failure Modes

| Error | Cause |
|-------|-------|
| `no executor registered for action_type` | Action type not in registry; check startup log |
| `does not start with shell:` | Wrong resource prefix for action type |
| `exec: binary name is empty` | Resource `exec:` missing binary name |
| `git: repository is empty` | Resource `git:` missing repo path |
| `continuation not in executable state` | State not approved/queued/resumed |
| `approval not approved` | Tried to resume without approval |

---

## Risky Shell Patterns (Trust Evaluator)

These trigger escalation even in `dev` environment:

`curl |sh`, `wget |sh`, `rm -rf`, `mkfs`, `dd if=`, `:(){:|:&};:`, `chmod -R 777`, `chown -R`, `sudo su`, `passwd root`, `killall`, `pkill -9`, `reboot`, `shutdown`, `> /etc/`, `> /var/`, `/dev/sd`, `nc -e`, `bash -i`

---

## Unimplemented Action Types

These are documented but not implemented in V1:

- `github.*` — GitHub API executor
- `ci.*` — CI system executor
- `git.force_push` — force push executor

Using these in policy is harmless (they never match a registered executor). Using them in a continuation results in `SKIP no executor`.

---

## Log Prefixes

| Prefix | When it appears |
|--------|---------------|
| `EXEC pickup` | Orchestrator picks up continuation |
| `EXEC completed=success/timeout/failed` | Execution finishes |
| `SKIP no executor` | No executor for action type |
| `APPROVAL created/approved/denied/resumed` | Approval lifecycle |
| `QUEUE enqueue/cancel/pause/resume` | Queue operations |
| `SWEEP` | Background cleanup |

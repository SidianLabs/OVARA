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
| `ready` | Orchestrator picked up |
| `executed` | Execution completed |
| `denied` | Human denied |
| `expired` | Past expiry time |
| `cancelled` | Explicitly cancelled |
| `resumed` | Retry after failure |

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

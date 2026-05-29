# Runtime Gateway Troubleshooting Guide

Practical guide for diagnosing issues with the Ovara Runtime Gateway.

**Gateway port:** 8080 (default)

---

## Reading the Logs

The gateway writes operational logs to stdout/stderr. In production, redirect these to a log file.

**Key log prefixes** (see in order):

```
SKIP no executor      → action type has no executor registered
EXEC pickup           → orchestrator picked up a continuation
EXEC completed=success → command ran successfully
EXEC completed=timeout → command timed out
EXEC completed=failed  → command failed
APPROVAL created      → escalation was created
APPROVAL approved     → human approved
APPROVAL denied       → human denied
APPROVAL resumed      → approved action was resumed
QUEUE enqueue         → continuation was enqueued
QUEUE cancel          → continuation was cancelled
QUEUE pause/resume    → queue was paused/resumed
SWEEP                 → background cleanup ran
```

Decision details (JSON lines) go to `var/log/decisions.jsonl`, not stdout.

---

## Quick Diagnostics

### Is the gateway running?

```bash
curl -s http://localhost:8080/health
# {"status":"ok"} means the gateway HTTP server is responding
```

### Is the gateway ready (all stores initialized)?

```bash
curl -s http://localhost:8080/ready
# Returns readiness status including whether stores are configured
```

### What's in the queue?

```bash
curl -s http://localhost:8080/v1/continuations/queue | jq '.count, .queue[].continuation_id'
```

### What's the gateway status?

```bash
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state}'
```

### How many approvals are pending?

```bash
curl -s http://localhost:8080/v1/approval/pending | jq '.count'
```

---

## Common Issues

### 1. Action returns `deny` but I expected `allow`

**Check:**
- The policy rules in effect (`GET /v1/policy/rules`)
- The `environment` field in your request (is it `production`?)
- Whether a catch-all rule is matching (`*` in `production` defaults to escalate/deny)

```bash
# Simulate what decision your request would get
curl -s -X POST http://localhost:8080/v1/policy/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:ls",
    "environment": "dev"
  }' | jq '.decision, .reason_codes'
```

### 2. `no executor registered for action_type`

**Meaning:** The orchestrator picked up a continuation, but no executor is registered for that action type. The action will never run.

**Causes:**
- Action type was never registered (not in startup log `action_types=`)
- Typo in action type string (`git.push` vs `git_push`)

**Check the registered executors** in startup logs:
```
execution orchestrator started (poll_interval=2s, action_types=[shell, exec, git.push, git.pull])
```

**If an unimplemented action type is in a continuation:**
- `SKIP no executor registered for action_type=github.push` — GitHub executor not implemented
- `SKIP no executor registered for action_type=git.force_push` — force push not implemented

**Fix:** Either remove the continuation or register a new executor for that action type.

### 3. Continuation not executing after approval

**Flow:** `escalate` → approval created → approved → resumed → continuation should be picked up by orchestrator

**Check:**
1. Is the orchestrator running? (check startup logs for `execution orchestrator started`)
2. Is the queue paused?
   ```bash
   curl -s http://localhost:8080/v1/continuations/queue | jq '.queue_paused'
   ```
   If `true`: `POST /v1/continuations/queue/resume`
3. Is the continuation in the right state?
   ```bash
   curl -s http://localhost:8080/v1/continuations/{id} | jq '.state'
   ```
   Must be `approved`, `queued`, or `resumed` to execute.
4. Was the resume actually called?
   ```bash
   # Look for "APPROVAL resumed" in gateway logs
   # And "EXEC pickup" after it
   ```

### 4. `invalid resource: does not start with shell:`

**Meaning:** The `resource` field in the action request does not have the correct prefix for its action type.

**Fix:** Ensure resources use the correct prefixes:

| Action Type | Correct Resource | Wrong |
|-------------|-----------------|-------|
| `shell` | `shell:ls -la` | `ls -la` or `exec:ls` |
| `exec` | `exec:curl http://example.com` | `curl http://example.com` |
| `git.push` / `git.pull` | `git:origin/main` | `origin/main` |

### 5. `exec:` command with pipes fails

**Cause:** `exec:` uses direct subprocess, not a shell. Pipes (`|`) and redirects (`>`, `&&`) require shell interpretation.

**Fix:** Use `shell:` for commands that need shell features:
```
# Wrong:
exec:curl http://example.com | sh

# Correct:
shell:curl http://example.com | sh
```

### 6. Git push/pull fails

**Common errors in `EXEC completed=failed`:**

- `git: repository is empty` — no repo path after `git:` prefix. Use `git:origin/main`, not `git:`
- `git: not a git repository` — the path is not a valid git repo. Must be an absolute or working-directory-relative path that is a `git` repo root
- `git: could not resolve repository path` — path resolution failed

**For git push:**
```
git:origin/main  →  git push origin main
```
The `origin` is the remote name, `main` is the branch. Both must exist.

### 7. Gateway returns 500 or hangs

**Check:**
1. Is the gateway process still running?
   ```bash
   ps aux | grep ovara-gateway
   ```
2. Are any stores failing to initialize? Check startup logs for `warning: failed to create` lines
3. Check for panic in logs (stderr)

### 8. Policy changes not taking effect

The gateway loads policy at startup and can hot-reload if `policy_refresh_interval` is set in config.

**To trigger a manual reload:**
```bash
# Check current policy version
curl -s http://localhost:8080/v1/runtime/status | jq '.policy_version'

# Force a reload by touching the policy file (if using file-based policy)
# Or restart the gateway
```

### 9. `continuation not in executable state` on resume

**Meaning:** The continuation's current state does not allow execution.

**Check the current state:**
```bash
curl -s http://localhost:8080/v1/continuations/{id} | jq '.state'
```

**Executable states:** `approved`, `queued`, `resumed`

**Non-executable states:** `escalated` (needs approval first), `denied`, `expired`, `cancelled`, `executed`

### 10. Decision is `escalate` but no approval workflow

**This is correct behavior for `escalate`.** The gateway does not auto-create approvals. You must create one explicitly:

```bash
# Get the decision_id from the escalate response
DECISION_ID="dec_abc123"

# Create approval
curl -X POST http://localhost:8080/v1/approval/create \
  -H "Content-Type: application/json" \
  -d "{
    \"decision_id\": \"$DECISION_ID\",
    \"action_type\": \"shell\",
    \"resource\": \"shell:ls\",
    \"environment\": \"dev\",
    \"agent_id\": \"my-agent\"
  }"
```

---

## Debugging Checklist

```
[ ] Gateway is responding        → curl http://localhost:8080/health
[ ] Gateway is ready            → curl http://localhost:8080/ready
[ ] Request is well-formed      → Check resource prefix matches action_type
[ ] Policy is correct           → GET /v1/policy/rules; check environment
[ ] Executor is registered     → Look for action_types=[...] in startup log
[ ] Continuation state is right → GET /v1/continuations/{id} — must be executable
[ ] Queue is not paused        → GET /v1/continuations/queue — queue_paused must be false
[ ] Approval is approved        → GET /v1/approval/{id} — status must be "approved"
[ ] Resume was called          → Look for "APPROVAL resumed" + "EXEC pickup" in logs
```

---

## Log Investigation

### Find all events for a specific continuation

```bash
# Gateway logs
grep "continuation_id=cnt_abc123" /var/log/gateway.log

# Decision logs
grep "dec_xyz" var/log/decisions.jsonl | jq .
```

### Find all events for a specific agent

```bash
grep "agent_id=agt_001" var/log/decisions.jsonl | jq .
```

### Count approvals by status

```bash
curl -s http://localhost:8080/v1/approval/pending | jq '.count'
```

### Check sweep activity

```bash
# Look for SWEEP logs indicating background cleanup
grep "SWEEP" /var/log/gateway.log
```

---

## Getting Help

If stuck:

1. Check `docs/architecture/runtime_support_matrix.md` for what is actually supported
2. Check `docs/architecture/runtime_lifecycle.md` for how the system is supposed to flow
3. Run `go test ./...` in `runtime/gateway/` to verify the gateway builds and tests pass
4. Check `examples/` scripts for working examples of the full flow

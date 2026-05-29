# Ovara Runtime Gateway

Local runtime authorization layer for Ovara. Intercepts and evaluates autonomous agent actions before execution, returning allow, deny, or escalate decisions.

## Action Types Supported

- `shell` — shell command execution via system shell
- `exec` — direct subprocess execution (no shell wrapper)
- `git.push` — git push to remote repository
- `git.pull` — git pull from remote repository

For full support matrix (resource formats, default behavior, failure modes), see [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

For troubleshooting common issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Quick Start

```bash
# Build
cd runtime/gateway
go build -o ovara-gateway ./cmd/server

# Run gateway (uses default config)
./ovara-gateway

# Or with config path
OVARA_CONFIG=./etc/config.json ./ovara-gateway
```

## Architecture

```
Agent/SDK → POST /v1/runtime/check → Evaluator → Policy Store → Decision Response
                                     → Decision Logger
                                     → Receipt Stub Generator

Interceptor → GatewayClient → POST /v1/runtime/check
Interceptor → executes command only on allow decision
```

## API

### `POST /v1/runtime/check`

Evaluates an action before execution.

**Request:**

```json
{
  "action_type": "shell",
  "resource": "shell:git push origin main",
  "agent_identity": {
    "issuer": "ovara",
    "subject_id": "agt_001"
  },
  "capability_lease": {
    "lease_id": "cap_abc",
    "issuer": "ovara",
    "subject": "agt_001",
    "allowed_actions": ["shell", "exec", "git.push"],
    "resource_scope": "repo:acme/api",
    "expiry": "2026-05-25T00:00:00Z",
    "delegation_depth": 1
  },
  "environment": "dev"
}
```

**Response:**

```json
{
  "decision_id": "dec_abc123def456",
  "decision": "escalate",
  "reason_codes": ["escalate"],
  "trust_score": 0.5,
  "requires_approval": true,
  "receipt_stub": {
    "receipt_id": "rcpt_xyz",
    "action_digest": "sha256:abc123",
    "action_type": "shell",
    "resource": "shell:git push origin main",
    "policy_version": "v1-local",
    "issued_at": "2026-05-24T12:00:00Z"
  }
}
```

### `GET /health`

Returns gateway health status.

### `GET /ready`

Returns gateway readiness status.

## Interceptors

### Shell Interceptor

Wrap shell command execution through the gateway:

```go
import "ovara.runtime.gateway/interceptors/shell"

func main() {
    i := shell.New("http://localhost:8080", "agent-001")
    result := i.Execute(ctx, "echo hello")
    if result.Decision == shell.DecisionAllow {
        fmt.Println(string(result.Output))
    }
}
```

### Git Interceptor

Wrap git operations through the gateway:

```go
import "ovara.runtime.gateway/interceptors/git"

func main() {
    i := git.New("http://localhost:8080", "agent-001")
    result := i.Push(ctx, "origin", "main")
    if result.Decision == git.DecisionAllow {
        // push succeeded
    }
}
```

## Configuration

Create `etc/config.json`:

```json
{
  "server_port": "8080",
  "policy_version": "v1-local",
  "policy_file": "./examples/sample_policy.json",
  "policy_refresh_interval": 10,
  "log_level": "info",
  "fail_closed": false,
  "decision_log_file": "var/log/decisions.jsonl"
}
```

All fields are optional. Defaults are used if not specified.

## Decision Outcomes

- `allow` — action is permitted and executed
- `deny` — action is blocked; command does not run
- `escalate` — action is blocked pending human approval; command does not run. Use the approval service to approve or deny.

## Approval Workflow

When an action returns `escalate`, create an approval request and await human decision:

```bash
# Create approval
curl -X POST http://localhost:8080/v1/approval/create \
  -H "Content-Type: application/json" \
  -d '{"decision_id":"dec_abc123","action_type":"shell","resource":"shell:git push","environment":"dev"}'

# List pending approvals
curl http://localhost:8080/v1/approval/pending

# Approve an action
curl -X POST http://localhost:8080/v1/approval/{approval_id}/approve \
  -H "Content-Type: application/json" \
  -d '{"resolved_by":"admin@example.com"}'

# Resume an approved action
curl -X POST http://localhost:8080/v1/approval/{approval_id}/resume
```

Approval states:
- `pending` — awaiting human review
- `approved` — action is authorized; use resume endpoint to proceed
- `denied` — action is blocked permanently

## Policy Behavior

Default rules (from `sample_policy_local.json`):

- `shell` in `local` environment → allow (harmless read-only commands)
- `shell` in `production` environment → deny (too risky)
- `shell` in `dev` environment → escalate (risky but recoverable)
- `git.pull` in any environment → allow (read-only, always safe)
- `git.push` in any environment → escalate (modifies remote state, requires approval)
- `exec` in any environment → escalate (direct subprocess, requires approval)
- catch-all in `production` → escalate (requires explicit approval)

## Logging

Runtime operations are logged to stderr and stdout in a structured key=value format:

- `EXEC pickup` — orchestrator picks up a continuation for execution
- `EXEC completed` — execution finished (success, timeout, or failure)
- `SKIP no executor` — continuation has no registered executor for its action type
- `APPROVAL created/approved/denied/resumed` — approval workflow events
- `SWEEP` — background cleanup operations

Decision logs are written to the configured `decision_log_file` as JSON lines. Each entry includes the timestamp, full request, and full response.

## Phase 1 Scope

- runtime gateway HTTP service
- canonical action request/response models
- local policy store (in-memory, configurable)
- allow/deny/escalate decisions
- structured decision logging
- receipt stub generation
- unit tests for core logic

## Phase 2 Scope

- gateway client package for calling runtime checks
- shell interceptor adapter
- git interceptor adapter
- end-to-end interceptor tests
- UUID-based decision ID generation

## Phase 3 Scope

- local approval service with in-memory store
- approval request model tied to decision
- approve/deny/resume endpoints for escalated actions
- approval workflow tests

## Non-Phase-1/2/3

- advanced policy language
- machine identity federation
- anomaly scoring
- hosted multi-tenant features
- browser integrations
- payment flows

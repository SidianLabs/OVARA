# Ovara Runtime Gateway

Local runtime authorization layer for Ovara. Intercepts and evaluates autonomous agent actions before execution, returning allow, deny, or escalate decisions.

## Action Types Supported

- `shell` — shell command execution
- `git.push`, `git.pull`, `git.force_push` — Git mutation actions
- `github.push`, `github.pr`, `github.merge`, `github.delete_branch` — GitHub actions
- `ci.deploy`, `ci.build_trigger`, `ci.approval` — CI/CD deployment actions

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
  "action_type": "github.push",
  "resource": "repo:acme/api:branch/main",
  "agent_identity": {
    "issuer": "ovara",
    "subject_id": "agt_001"
  },
  "capability_lease": {
    "lease_id": "cap_abc",
    "issuer": "ovara",
    "subject": "agt_001",
    "allowed_actions": ["github.push"],
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
    "action_type": "github.push",
    "resource": "repo:acme/api:branch/main",
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

Available interceptors under `interceptors/`:

- `shell` — shell command execution with gateway check before running
- `git` — git operations (push, pull, force-push) with gateway check

## Configuration

Create `etc/config.json`:

```json
{
  "server_port": "8080",
  "policy_version": "v1-local",
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

Default rules:

- shell commands escalate in all environments
- GitHub merge, delete_branch escalate in all environments
- CI deploy actions escalate in all environments
- production environment actions escalate by default

## Logging

Decisions are written to the configured `decision_log_file` as JSON lines. Each entry includes the timestamp, full request, and full response.

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
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

# Run (uses default config)
./ovara-gateway

# Or with config path
OVARA_CONFIG=./etc/config.json ./ovara-gateway
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

- `allow` — action is permitted
- `deny` — action is blocked
- `escalate` — action requires human approval before execution

## Policy Behavior

Default rules:

- shell commands escalate in all environments
- GitHub merge, delete_branch escalate in all environments
- CI deploy actions escalate in all environments
- production environment actions escalate by default

## Logging

Decisions are written to the configured `decision_log_file` as JSON lines. Each entry includes the timestamp, full request, and full response.

## Architecture

```
Agent/SDK → POST /v1/runtime/check → Evaluator → Policy Store → Decision Response
                                   → Decision Logger
                                   → Receipt Stub Generator
```

## Phase 1 Scope

- runtime gateway HTTP service
- canonical action request/response models
- local policy store (in-memory, configurable)
- allow/deny/escalate decisions
- structured decision logging
- receipt stub generation
- unit tests for core logic

## Non-Phase-1

- advanced policy language
- machine identity federation
- anomaly scoring
- hosted multi-tenant features
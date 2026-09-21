# Runtime API

The Ovara Runtime Gateway exposes a versioned HTTP API under `/v1/`.
All endpoints accept and return JSON. Operator endpoints (approval,
continuation management, recovery, shield) require a bearer token.

## Authentication

```http
Authorization: Bearer <operator_token>
```

The operator token is configured via `operator_tokens` in
[`etc/config.json`](../../runtime/gateway/etc/config.json). For local
development, the token is optional. For production deployments, the
token **must** be set and `auth_enabled: true` in the config.

When `auth_enabled` is `false`, all endpoints are open. This is the
default for local development only.

## Transport

The gateway serves plain HTTP — there is no TLS in the binary.
Production deployments must terminate TLS in front of the gateway
(reverse proxy or load balancer). Operator tokens are flat bearer
tokens with a single privilege level; there is no RBAC on the gateway.

## Content Types

```http
Content-Type: application/json
Accept: application/json
```

## Error Responses

Errors return a JSON body with a flat shape (see
[`internal/api/errors.go`](../../runtime/gateway/internal/api/errors.go)):

```json
{
  "error": "action_type is required",
  "code": "validation_failed",
  "message": "optional extra context"
}
```

`error` carries the human-readable message; `code` and `message` are
optional and only present on some endpoints.

Common HTTP statuses:

| HTTP | Meaning |
|------|---------|
| 400 | Request body failed validation |
| 401 | Missing or invalid bearer token |
| 404 | Resource does not exist |
| 405 | Method not allowed on this path |
| 409 | State conflict (e.g., already approved) |
| 422 | Semantically invalid entity |
| 500 | Internal server error |

## Endpoints

### Health & Status

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check (always 200 if process is up) |
| `GET` | `/ready` | Readiness check (200 when gateway is ready) |
| `GET` | `/v1/runtime/status` | Full gateway status dump |
| `GET` | `/v1/runtime/health` | SLA health diagnostics |
| `GET` | `/v1/runtime/metrics` | Decision and heartbeat metrics |
| `GET` | `/v1/runtime/integrity` | Data integrity check |
| `GET` | `/v1/runtime/snapshot` | Timepoint snapshot of state |
| `GET` | `/v1/runtime/summary` | Aggregate summary |
| `GET` | `/v1/runtime/trace` | Cross-entity trace |
| `GET` | `/v1/runtime/required_action_fields` | Schema for action requests |
| `GET` | `/v1/runtime/agent/{agent_id}/recent` | Recent decisions for an agent |
| `GET` | `/v1/audit/export` | Export audit data |

### Decision

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/runtime/check` | Evaluate single action |
| `POST` | `/v1/runtime/batch-check` | Evaluate multiple actions |
| `GET` | `/v1/runtime/decision/{id}` | Retrieve cached decision |

### Approvals

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/approval/create` | Create approval request |
| `GET` | `/v1/approval/{id}` | Get approval |
| `POST` | `/v1/approval/{id}/approve` | Approve escalation |
| `POST` | `/v1/approval/{id}/deny` | Deny escalation |
| `POST` | `/v1/approval/{id}/resume` | Resume an approved continuation |
| `GET` | `/v1/approval/pending` | List pending approvals |
| `GET` | `/v1/approvals` | List approvals |

### Continuations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/continuations` | List continuations |
| `GET` | `/v1/continuations/{id}` | Get continuation |
| `GET` | `/v1/continuations/stats` | Continuation statistics |
| `GET` | `/v1/continuations/queue` | Queue contents |
| `POST` | `/v1/continuations/sweep` | Sweep stale continuations |
| `POST` | `/v1/continuations/recover-executing` | Recover stuck executions |
| `POST` | `/v1/continuations/{id}/recover-executing` | Recover one stuck execution |
| `POST` | `/v1/continuations/queue/pause` | Pause the queue |
| `POST` | `/v1/continuations/queue/resume` | Resume the queue |
| `POST` | `/v1/continuations/{id}/enqueue` | Enqueue a continuation |
| `POST` | `/v1/continuations/{id}/cancel` | Cancel a continuation |
| `POST` | `/v1/continuations/{id}/retry` | Retry a continuation |
| `POST` | `/v1/continuations/{id}/execute` | Execute a continuation directly |
| `POST` | `/v1/continuations/retry` | Bulk retry |
| `POST` | `/v1/continuations/cancel` | Bulk cancel |

### Executions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/executions/{id}` | Get execution |
| `GET` | `/v1/executions` | List executions |
| `GET` | `/v1/executions/stats` | Execution statistics |

### Receipts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/receipts/{id}` | Get receipt |
| `GET` | `/v1/receipts` | List receipts |
| `GET` | `/v1/receipts/decision/{decision_id}` | Receipts for a decision |

### Events

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/events` | List events |
| `GET` | `/v1/events/export` | Export events |
| `GET` | `/v1/events/{id}` | Get event |

### Policy

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/policy/validate` | Validate a policy document |
| `POST` | `/v1/policy/simulate` | Simulate policy against an action |
| `POST` | `/v1/policy/simulate-batch` | Batch simulation |
| `GET`/`POST` | `/v1/policy/diff` | Compare current vs candidate policy |
| `POST` | `/v1/policy/candidate/load` | Load a candidate policy |
| `POST` | `/v1/policy/candidate/promote` | Promote candidate to active |
| `GET` | `/v1/policy/rules` | List active rules |
| `GET` | `/v1/policy/history` | Policy version history |
| `GET` | `/v1/policy/history/entry` | Get a history entry |
| `POST` | `/v1/policy/rollback` | Roll back to a prior version |
| `POST` | `/v1/policy/restore` | Restore a policy version |

### Capabilities

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/capabilities` | List leases |
| `GET` | `/v1/capabilities/{id}` | Get lease |
| `GET` | `/v1/capabilities/history` | Lease history |
| `POST` | `/v1/capabilities/track` | Track a lease |
| `POST` | `/v1/capabilities/revoke` | Revoke a lease |
| `POST` | `/v1/capabilities/revoke-by-subject` | Revoke all leases for a subject |

### Shield & Trust

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/shield/status` | Shield status |
| `GET` | `/v1/shield/status/{agent_id}` | Per-agent shield status |
| `POST` | `/v1/shield/restrict/{agent_id}` | Restrict agent |
| `POST` | `/v1/shield/unrestrict/{agent_id}` | Unrestrict agent |
| `GET` | `/v1/trust/context` | Agent trust context |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/admin/reconcile/continuations` | Reconcile continuation state |
| `POST` | `/v1/admin/reconcile/executions` | Reconcile execution state |
| `POST` | `/v1/admin/compact` | Compact stores |
| `POST` | `/v1/admin/sweep/continuations` | Sweep continuations |
| `POST` | `/v1/admin/sweep/events` | Sweep events |

## Rate Limits

The gateway does not enforce rate limits in the V1 single-binary
distribution. The hosted cloud control plane (Fastify + @fastify/rate-limit)
enforces a default of 1000 req/min per API key, configurable per
organization.

## Versioning

The API version is the first path component (`/v1/`). Breaking changes
will require a new major version (`/v2/`). The current major version is
**v1** and is considered stable for the V1.0.0 release.

## SDKs

TypeScript and Python SDKs are available and provide typed wrappers
around the HTTP API:

- [TypeScript SDK](../../sdk/typescript/)
- [Python SDK](../../sdk/python/)

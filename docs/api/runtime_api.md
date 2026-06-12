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

## Content Types

```http
Content-Type: application/json
Accept: application/json
```

## Error Responses

All errors return a JSON body with this shape:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "action_type is required",
    "details": {
      "field": "action_type",
      "reason": "required"
    }
  }
}
```

Standard error codes:

| Code | HTTP | Meaning |
|------|------|---------|
| `validation_failed` | 400 | Request body failed validation |
| `unauthorized` | 401 | Missing or invalid bearer token |
| `forbidden` | 403 | Token lacks required scope |
| `not_found` | 404 | Resource does not exist |
| `conflict` | 409 | State conflict (e.g., already approved) |
| `internal` | 500 | Internal server error |

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
| `POST` | `/v1/approval/{id}/approve` | Approve escalation |
| `POST` | `/v1/approval/{id}/deny` | Deny escalation |
| `GET` | `/v1/approval/list` | List approvals |

### Continuations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/continuations/list` | List continuations |
| `GET` | `/v1/continuations/{id}` | Get continuation |
| `POST` | `/v1/continuations/retry` | Retry failed continuations |
| `POST` | `/v1/continuations/cancel` | Cancel continuations |
| `POST` | `/v1/continuations/recover-executing` | Recover stuck executions |

### Executions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/executions/{id}` | Get execution |
| `GET` | `/v1/executions/list` | List executions |

### Receipts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/receipts/{id}` | Get receipt |
| `GET` | `/v1/receipts/list` | List receipts |
| `GET` | `/v1/audit/export` | Export audit data |

### Policy

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/policy/simulate` | Simulate policy against an action |
| `POST` | `/v1/policy/compare` | Compare two policies |

### Shield & Trust

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/shield/status` | Shield status |
| `POST` | `/v1/shield/restrict/{id}` | Restrict agent |
| `POST` | `/v1/shield/unrestrict/{id}` | Unrestrict agent |
| `GET` | `/v1/trust/context` | Agent trust context |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/admin/orchestrator/pause` | Pause orchestrator |
| `POST` | `/v1/admin/orchestrator/resume` | Resume orchestrator |

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

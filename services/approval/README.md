# Ovara Approval Service

Standalone microservice for managing approval workflows. Listens for approval requests from gateways, persists pending approvals, and resolves them on operator action.

## Auth

All endpoints except `/health` require `Authorization: Bearer <token>`. Configure tokens with the `-tokens` flag (comma-separated) or the `OVARA_APPROVAL_TOKENS` env var. With no tokens configured the service runs in open mode and logs a loud warning at startup.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | /v1/approvals | Create approval |
| GET | /v1/approvals | List approvals (`state`, `gateway_id`, `agent_id`, `limit` (default 100, max 1000), `offset`) |
| GET | /v1/approvals/:id | Retrieve approval |
| POST | /v1/approvals/:id/approve | Approve |
| POST | /v1/approvals/:id/deny | Deny |
| POST | /v1/approvals/expire | Expire pending approvals older than `before` (RFC3339; default 30m ago) |
| GET | /v1/approvals/stats | Approval count |
| GET | /health | Health check (unauthenticated) |

A background sweeper auto-expires pending approvals past their `expires_at` every minute and evicts expired entries from the store. Request bodies are capped at 10MB.

## Build

```bash
go build -o approval-service ./cmd/server/
```

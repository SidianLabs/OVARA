# Ovara Approval Service

Standalone microservice for managing approval workflows. Listens for approval requests from gateways, persists pending approvals, and resolves them on operator action.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | /v1/approvals | Create approval |
| GET | /v1/approvals | List pending approvals |
| POST | /v1/approvals/:id/approve | Approve |
| POST | /v1/approvals/:id/deny | Deny |

## Build

```bash
go build -o approval-service ./cmd/server/
```

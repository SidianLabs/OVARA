# Ovara Receipt Storage Service

Durable receipt archive with append-only semantics and cryptographic verification.

## Auth

All endpoints except `/health` require `Authorization: Bearer <token>`. Configure tokens with the `-tokens` flag (comma-separated) or the `OVARA_RECEIPT_TOKENS` env var. With no tokens configured the service runs in open mode and logs a loud warning at startup.

## Signature verification

Pass the gateway's HMAC key via `-key` or `OVARA_RECEIPT_HMAC_KEY`. Receipts are verified against the gateway's RFC 0003 canonical payload (`receipt_id|decision_id|action_digest|action_type|resource|agent_id|decision|policy_version|trust_score|issued_at`). Submit the gateway-issued `receipt_id`, `action_digest`, and `policy_version` at ingest so verification is byte-exact. Without a key, `verify` reports receipts as unverifiable.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | /v1/receipts | Archive receipt |
| GET | /v1/receipts | List receipts (`organization_id`, `gateway_id`, `decision`, `action_type`, `start_date`, `end_date`, `limit` (default 100, max 1000), `offset`) |
| GET | /v1/receipts/:id | Retrieve receipt |
| GET | /v1/receipts/:id/verify | Verify receipt signature |
| GET | /v1/receipts/stats | Receipt counts (`organization_id` optional) |
| GET | /health | Health check (unauthenticated) |

Request bodies are capped at 10MB.

## Build

```bash
go build -o receipt-storage ./cmd/server/
```

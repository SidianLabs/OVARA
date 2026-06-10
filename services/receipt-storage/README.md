# Ovara Receipt Storage Service

Durable receipt archive with append-only semantics and cryptographic verification.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | /v1/receipts | Archive receipt |
| GET | /v1/receipts/:id | Retrieve receipt |
| POST | /v1/receipts/:id/verify | Verify receipt signature |

## Build

```bash
go build -o receipt-storage ./cmd/server/
```

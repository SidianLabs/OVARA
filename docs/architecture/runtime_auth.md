# Runtime Gateway — Operator Authentication

## Overview

The runtime gateway supports local-first, token-based authentication for operator API
access. Authentication is enforced by a single HTTP middleware that wraps the entire
request mux, so every route is covered by one consistent check.

This is intentionally simple and local-first: static operator tokens loaded from config,
compared in constant time. There is no external identity provider, session store, or
token issuance service — consistent with the gateway's local-first constraints.

## Configuration

Two config fields control auth (see `internal/config/config.go`):

| Field | JSON key | Type | Default | Meaning |
|-------|----------|------|---------|---------|
| `AuthEnabled` | `auth_enabled` | bool | `false` | Master switch for auth enforcement |
| `OperatorTokens` | `operator_tokens` | `[]string` | `[]` | Accepted bearer tokens |

Example `config.json`:

```json
{
  "auth_enabled": true,
  "operator_tokens": ["op_live_a1b2c3...", "op_live_d4e5f6..."]
}
```

Tokens are arbitrary opaque strings. Generate them with a cryptographically secure
source (e.g. `openssl rand -hex 32`) and treat them as secrets — keep them out of
version control and rotate by editing config and restarting.

## Behavior

### Enforcement modes

| `auth_enabled` | `operator_tokens` | Result |
|----------------|-------------------|--------|
| `false` | (any) | **Open mode** — no auth enforced. Startup logs the open state. |
| `true` | non-empty | **Enforced** — requests require a valid bearer token. |
| `true` | empty | **Open mode + loud warning** — misconfiguration; gateway runs open and logs `AUTH WARNING` at startup. |

The empty-tokens-while-enabled case runs open by design (so a misconfigured deploy fails
operational rather than locking everyone out), but emits a prominent startup warning so
the gap is visible. Do not rely on it for production.

### Request flow (when enforced)

1. Open/health paths bypass auth: `/health`, `/ready`, `/v1/runtime/status`.
2. The `Authorization` header must be present and use the `Bearer <token>` scheme.
3. The provided token is compared against each configured token using
   `crypto/subtle.ConstantTimeCompare` to avoid timing side channels.
4. On success the request proceeds; otherwise a `401` JSON error is returned.

### Responses

| Condition | Status | Body |
|-----------|--------|------|
| Valid token | passes through | (handler response) |
| Missing `Authorization` header | `401` | `{"error":"missing authorization header"}` |
| Non-bearer scheme | `401` | `{"error":"invalid authorization format — use: Authorization: Bearer <token>"}` |
| Empty token after `Bearer ` | `401` | `{"error":"token is empty"}` |
| Unknown token | `401` | `{"error":"invalid token"}` |

Token values are never written to logs.

## Open (unauthenticated) paths

These paths are always reachable without a token, by design:

- `GET /health` — liveness
- `GET /ready` — readiness
- `GET /v1/runtime/status` — coarse runtime status (no sensitive payloads)

All other endpoints — including mutating operator actions (approve/deny/resume/retry/
enqueue/cancel/execute, queue pause/resume, admin/*) and sensitive reads (audit export,
snapshot) — require a valid token when auth is enforced.

## Example

```bash
# Enforced gateway
curl -H "Authorization: Bearer op_live_a1b2c3..." \
  http://localhost:8080/v1/continuations

# Missing/invalid token -> 401
curl http://localhost:8080/v1/continuations
```

## Security notes

- Constant-time token comparison prevents timing attacks on token guessing.
- Tokens are never logged.
- This is bearer-token auth over whatever transport the operator terminates; run the
  gateway behind TLS in any non-local deployment.
- There is currently a single operator privilege level (any valid token has full
  operator access). A read-only vs operator role split is a possible future extension;
  it is not implemented today.

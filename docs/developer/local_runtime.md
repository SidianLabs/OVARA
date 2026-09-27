# Local Runtime

The gateway is a single Go binary (`runtime/gateway/cmd/server` —
`./examples/start_gateway.sh` runs it via `go run`); the executor
proxy is `proxy/cmd/ovara-proxy`. The unified `proxy/cmd/ovara` CLI runs
both halves from one directory (`ovara init` + `ovara run`).

## Config

The binary reads `OVARA_CONFIG` — a path **relative to the gateway
working directory** — falling back to `etc/config.json`. Only two env
vars matter: `OVARA_CONFIG`, `OVARA_ENVIRONMENT` (plus
`OVARA_SANDBOX_ENABLED`). `OVARA_PORT`, `OVARA_POLICY_FILE`, and
`OVARA_POLICY_REFRESH_INTERVAL` do nothing; set `server_port`,
`policy_file`, `policy_refresh_interval` in the JSON.

The fields you'll touch first (full list in
[`examples/sample_config.json`](../../examples/sample_config.json)):

| Field | Meaning |
|-------|---------|
| `server_port`, `listen_addr` | Bind address. Open auth requires loopback. |
| `policy_file` | Allow/escalate/deny rules (see `examples/sample_policy_local.json`) |
| `fail_closed` | `true` = refuse to serve if the policy fails to load. Set it for anything real. |
| `auth_enabled` + `operator_tokens`/`agent_tokens` | Bearer auth. Empty token lists = deny-all. `false` only boots on loopback. |
| `decision_log_file`, `receipts_file`, `approvals_file`, `events_file`, `continuations_file`, `execution_file`, `capabilities_file`, `enrollment_file` | Local state under `var/` — unset means in-memory. |
| `identity_registry_file` | Persistence for the sealed identity registry (revocations, seq-chained) |
| `heartbeat_interval_secs` | Enrollment heartbeat cadence (local enrollment only) |
| `enable_host_executors` | Opt-in: actually run shell/git commands on this host |
| `github_token`, `ci_token` + `ci_webhook_url` | Wire the GitHub/CI executors |
| `receipt_signing_key` | HMAC key for `sig_v1` receipt signatures. Unset = random per-process key, so receipts can't be verified after restart — set it for anything real. Ed25519 (`edsig_v1`) signatures come from the enrolled gateway identity key, not this field. |

## Executors

Out of the box, **no executor is armed**: host executors are off until
`enable_host_executors: true`, the sandbox executor needs
`OVARA_SANDBOX_ENABLED=true`, and GitHub/CI executors need their tokens.
Without them an *approved* action stays queued — `check`, `escalate`,
`approve`, and receipts all still work.

## What to look at

- `var/log/decisions.jsonl` — every check with reason codes
- `var/data/receipts.json` — signed receipts (`sig_v1` HMAC; `edsig_v1` Ed25519 once the gateway has an enrolled identity key)
- `var/data/events.jsonl` — hash-chained event journal
- `GET /v1/runtime/status` — gateway id, enrollment state, shield counts
- `GET /v1/trust/context?agent_id=…` — an agent's trust score

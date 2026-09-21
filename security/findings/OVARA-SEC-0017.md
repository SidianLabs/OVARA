# OVARA-SEC-0017 — Shipped gateway defaults are open: 0.0.0.0, no auth; missing config fails open

**Severity:** CRITICAL (deployment-dependent — standalone/shipped configs);
would-be HIGH as pure design flaw
**Component:** runtime/gateway/internal/config/config.go:122-199,
etc/config.json, etc/sample_config.json, server.go:513-516
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Evidence
- `config.Default()`: `AuthEnabled:false`, `OperatorTokens:[]`,
  `ListenAddr:""` → binds `":"+port` (all interfaces), every `/v1/*`
  route unauthenticated (only /health,/ready skip — intended).
- `config.Load(path)`: `os.ReadFile` error → `return Default(), nil` —
  a missing/misnamed config SILENTLY yields the open default.
- Shipped `etc/config.json` + `sample_config.json` contain no
  `auth_enabled`/`operator_tokens`/`listen_addr`.
- No TLS on the listener — bearer tokens cleartext off-loopback.
- `fail_closed` config flag is read but unused (dead knob).

## Root cause
Secure defaults were applied only in the `ovara init` generator, not in
the gateway binary/defaults themselves — the fail-open `Load` fallback
means even the hardened path can silently degrade if the config path
is wrong.

## Security impact
Run the shipped binary or use the shipped configs → SEC-0016 RCE,
SEC-0020 policy takeover, audit destruction — all unauthenticated from
the network. The `ovara init`-generated config (loopback+token+auth)
is the only hardened path; everything else ships open.

## Proposed fix
- `Load` must FAIL on missing/unreadable config (or loudly refuse
  privileged endpoints) — never silently `Default()`.
- Ship `etc/config.json` with auth_enabled+generated token+loopback;
  refuse `0.0.0.0` bind with auth disabled unless an explicit
  `i_know_this_is_open` flag is set.
- Warn when `auth_enabled=false`; TLS or loopback-only for bearer
  tokens.

## Regression test
Start with missing config → process refuses/exits nonzero; start with
shipped etc config → auth required.

## Residual risk
Operators can still deliberately run open — must be a loud opt-in.


## Remediation (P0.5 — VERIFIED)

`config.Load` returns errors on missing/unreadable/malformed config — no
silent `Default()`. `ValidateStartup` runs before bind: auth disabled on a
non-loopback or empty bind is refused unless `unsafe_no_auth=true` is set
explicitly. Shipped etc/*.json bind 127.0.0.1 with auth_enabled=true.
`ovara init` generates real operator+agent tokens. Initial policy-file load
failure is now fatal (no silent fallback to the built-in default policy).

Regression tests: `config/sec0017_test.go` (missing, malformed, no-auth bind
matrix, unsafe opt-in). Live replay: missing config → fatal; malformed →
fatal; auth_enabled=false on 0.0.0.0 → refused.

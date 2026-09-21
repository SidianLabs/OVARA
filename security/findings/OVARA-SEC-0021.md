# OVARA-SEC-0021 — Nonce cache global, non-persistent, moot against unsigned requests

**Severity:** MEDIUM
**Component:** evaluator/evaluator.go:170-197 nonceCache
**Status:** CONFIRMED (static)

## Evidence
Nonce cache is a global in-memory map keyed by raw nonce string, 5-min
TTL, swept lazily. Requests are unsigned → a real attacker rewrites
`issued_at` or mints fresh nonces, so the cache only stops byte-identical
replays ≤5min. Restart wipes it entirely. Global keying enables
cross-agent DoS: pre-register common nonces to deny legitimate requests
sharing them for 5min.

## Root cause
Replay protection was bolted onto an unsigned request format — without
request authentication, freshness checks protect nothing.

## Security impact
Illusion of replay protection; restart opens a replay window; low-grade
cross-agent denial of service.

## Proposed fix
Scope nonce cache per-agent (once identity is real — SEC-0019/P1.1),
persist it, or accept-and-document it as advisory. Real fix is signed
requests/execution-identity tokens where replay is meaningless.

## Regression test
Restart gateway → replayed signed request still rejected; forged-nonce
DoS can't block another agent.

## Residual risk
Until requests are signed, replay protection is cosmetic by design.

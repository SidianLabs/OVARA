# OVARA-SEC-0014 — Approvals are not bound to the exact request (no body/params hash)

**Severity:** MEDIUM
**Component:** runtime/gateway/internal/approval/service.go +
proxy held-request flow
**Status:** CONFIRMED (state machine tested live; binding gap is structural)

## Evidence (live + static)
- Approval API state machine is sound: unauthenticated → 401, bad token
  → 401, double-approve → rejected, approve-after-deny and
  deny-after-approve → rejected, unknown id → 404, transitions atomic.
- BUT the approval object binds only (action_type, environment-ish
  context) — there is no hash of the exact request (method, URL, headers,
  body, git ref) stored at escalation time and compared at consumption.
- The proxy pins the approval_id it created to ITS held request, so
  in-proxy replay doesn't exist today — but any other consumer path
  (continuation API, batch, direct execution) can present an approval_id
  minted for a *different* request and there is nothing to check it
  against.
- `approval_id` in receipts is unsigned (SEC-0011), so even evidence of
  which approval was consumed is malleable.

## Root cause
Escalation records "an approval exists" not "this exact request was
approved". Binding requires hashing the normalized request at
decision/escalation time and verifying the same hash at consumption.

## Security impact
An approval minted for `GET https://api.github.com/x` can be spent on
`POST https://api.github.com/x` or a different body — approved ≠
executed. In multi-consumer paths this is privilege substitution; in
evidence it makes approval claims unfalsifiable.

## Proposed fix (P1 — approval↔request-hash binding)
- At escalate: store `request_hash = SHA256(normalized method|url|
  sorted-headers|body|git-ref)` inside the approval record (signed).
- At consume: recompute and compare; mismatch → deny + security event.
- Include request_hash in the signed receipt payload (receipt v2).

## Regression test
Approve request A → attempt consumption with mutated body/url/method/
ref → must deny; A itself must succeed.

## Residual risk
Normalization ambiguity (header order, chunked bodies) — solved by
canonicalizing at decision time and storing bytes-hash where streaming
makes normalization impossible.

# OVARA-SEC-0004 — Leases optional; identity fully self-asserted

**Severity:** MEDIUM
**Component:** runtime/gateway/internal/evaluator/evaluator.go:237-243,
internal/identity/validator.go
**Status:** CONFIRMED LIVE

## Reproduction (verified live)
`POST /v1/runtime/check` with `agent_identity = {"agent_id":"nobody",
"issuer":"untrusted","subject_id":"x"}` and NO `capability_lease` →
`{"decision":"allow","reason_codes":["policy_allow"]}` for
`http.request`@dev. Fake issuers are equally accepted. All trusted-issuer
machinery is bypassed by simply omitting the lease field.

Additional (code-verified): `lease.Subject` is never bound to
`agent_identity.subject_id` — a valid lease is a bearer token usable for
any claimed subject. `AgentIdentity` itself is unsigned (presence-checked
only).

## Root cause
nil lease is not an error path; identity validation only checks
non-empty strings. The proxy itself sends no lease — "egress-agent" is
self-asserted by design.

## Security impact
The documented "trusted issuer registry" gates only callers that bother
to present a lease. Any caller holding the gateway bearer token asserts
any identity. For the proxy path this is by-design (token = trust), but
the property must not be described as verified identity.

## Proposed fix (P1)
- Require a lease when `trusted_issuers` is configured, OR an explicit
  caller-class that is allowed to self-assert (the proxy, authenticated
  by its own credential class).
- Bind `lease.Subject == agent_identity.subject_id`.
- Sign `AgentIdentity` or stop presenting it as a verified object.
- Proxy should mint a short-lived signed execution-identity lease —
  this is the P1 "execution identity" primitive.

## Regression test
Request with no lease + allow-matching policy must be `deny`
(identity_unverified) under the strict mode; spoofed subject vs lease
subject must deny.

## Residual risk
The proxy bearer token is still a single shared credential for all
agent traffic — per-execution identity is the real fix (P1).

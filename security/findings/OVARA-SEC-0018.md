# OVARA-SEC-0018 — Flat single bearer token = gateway root; no requester/approver separation

**Severity:** HIGH
**Component:** runtime/gateway/internal/auth/middleware.go:79-92,
proxy/cmd/ovara/main.go:111-156 (init mints ONE token for both roles)
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Evidence
One token class (`operator_tokens`) unlocks every privileged route:
approve/deny/resume, continuation execute/pause/retry/cancel, policy
load/promote/rollback/restore, shield restrict/unrestrict, capability
revoke(-by-subject), admin sweep/compact/reconcile, audit export.
`ovara init` stores that SAME token as `operator_tokens[0]` (gateway)
AND `gateway_token` (proxy) — the credential the proxy uses to submit
checks can also approve them, mint shell approvals, and replace policy.

## Root cause
No role/scope concept in the auth middleware; init optimized for
single-operator convenience.

## Security impact
The "human approval" boundary collapses to "whoever holds the token"
— including the proxy process itself (its token is gateway-root) and
any local process that can read proxy env/config (SEC-0007). Combined
with SEC-0016 this is RCE; combined with SEC-0020 it's silent policy
takeover. Comments in the code acknowledge "a bounded agent could
approve its own escalations" — the only mitigations shipped are
loopback binding and token secrecy.

## Proposed fix
- Scoped tokens/roles: `agent` (check, approval create) vs `operator`
  (approve/deny/policy/shield/admin) vs `admin` (sweep/compact).
- `ovara init` mints separate proxy token (agent scope) and operator
  token; never stores operator token in proxy.json.
- Require operator role for executors, policy mutation, admin.

## Regression test
Agent-scope token → `approve` → 403; proxy token → `policy promote` →
403; operator token works.

## Residual risk
Role granularity beyond two classes is a P2 design question.


## Remediation (P0.5 — VERIFIED)

Two authorization domains: `operator_tokens` (gateway-root) and `agent_tokens`.
Agent tokens may only reach POST /v1/runtime/check, /v1/runtime/batch-check,
/v1/approval/create, and GET /v1/approval/{id} — every other route is
operator-only by default (new routes fail safe). Approval resolution,
continuations, policy mutation, admin, shield, capabilities, and all audit
reads are operator surfaces. `resolved_by` is derived from the authenticated
credential (`operator:label`), not the caller body. `ovara init` mints
separate operator/agent/proxy tokens; the proxy's gateway_token is an agent
token — it cannot approve its own escalations.

Regression tests: `auth/roles_test.go` full allow/deny matrix.
Live replay: agent self-approve → 403; agent policy load → 403.

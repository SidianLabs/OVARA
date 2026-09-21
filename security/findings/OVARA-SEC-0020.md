# OVARA-SEC-0020 — Policy takeover via candidate load/promote; admin endpoints enable audit destruction

**Severity:** HIGH in open deployments / MEDIUM for token holders
**Component:** handlers/policy.go candidate/load+promote+rollback+restore,
handlers/admin.go sweep/compact/reconcile
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)
it accepted + applied my test policy with only the flat token)

## Evidence
- `POST /v1/policy/candidate/load` accepts inline `policy_data` →
  `promote` swaps live rules in place. Only syntactic validation —
  `{"action_type":"*","environment":"*","allow":true}` is valid.
  No signing, no role check beyond the flat token (SEC-0018), no
  approval requirement for policy change.
- Admin routes: `/v1/admin/sweep/events` deletes the audit trail,
  `compact` rewrites stores, `reconcile/continuations` mass-expires
  pending approvals, bulk retry re-fires arbitrary failed commands —
  all same flat gate.
- `GET /v1/audit/export` dumps events+executions incl. stdout —
  full data exfil.

## Root cause
Policy mutation and destructive admin sit behind the same single
authentication factor as everything else; nothing treats policy
change as a security event requiring its own authorization.

## Security impact
In open mode (SEC-0017): unauthenticated remote policy replacement →
all decisions allow → credentialed proxy executes anything, PLUS audit
wiping to hide it. For token holders: same, trivially.

## Proposed fix
- Operator/admin role split (SEC-0018).
- Long-term: signed policy bundles (P2) — candidate promote requires
  signature from a trusted policy issuer.
- Make sweep/compact dual-control or append-only; alert events on
  policy promote + admin ops (P1.9 event model).

## Regression test
Agent-scope token → promote → 403; unsigned bundle → rejected once
signing lands; sweep requires admin scope.

## Residual risk
An operator-role holder can still take over — that's the role's job;
defense is audit + signed bundles.


## Remediation (P0.5 — VERIFIED)

Every mutating/privileged route is operator-only under the agent allowlist:
/v1/policy/candidate/*, /v1/policy/rollback, /v1/policy/restore,
/v1/admin/*, /v1/shield/*, /v1/capabilities/*, /v1/continuations/*,
/v1/executions*, audit/events/receipts exports. Auth-enabled with zero tokens
denies all (503, fail closed). Open mode on non-loopback requires explicit
unsafe_no_auth (SEC-0017).

Regression tests: `auth/roles_test.go` (agent denied on every mutation route).
Live replay: agent token candidate/load → 403; no-auth → 401; shipped config
binds loopback+auth.

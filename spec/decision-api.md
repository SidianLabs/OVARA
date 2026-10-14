# C3 — Decision API (spec 0.1)

The HTTP API a component (the proxy, the box, `ovara mcp wrap`, an SDK)
uses to have an action decided and, when a person must decide, to open,
follow and claim an approval. Base path `/v1`; JSON in and out. Schemas:
[`schemas/decision-request.schema.json`](schemas/decision-request.schema.json),
[`schemas/decision-response.schema.json`](schemas/decision-response.schema.json).
The full endpoint reference, including operator and identity endpoints, is
`docs/api/runtime_api.md`; this document fixes the part another
implementation must provide.

## 1. Credentials and roles

Every call carries `Authorization: Bearer <token>`. A token is either an
**agent** credential (what a proxy or a box holds) or an **operator**
credential (a person, or automation acting for one). An agent credential
reaches these routes and nothing else; every other route is operator-only,
and a new route is operator-only until listed here:

| Method and path | Agent may |
|---|---|
| `POST /v1/runtime/check` | have an action decided |
| `POST /v1/runtime/batch-check` | several at once |
| `POST /v1/runtime/outcome` | report how an action it was allowed to run went |
| `POST /v1/approval/create` | open an approval for its own escalated decision |
| `GET /v1/approval/{id}` | read its own approval |
| `POST /v1/approval/{id}/claim` | claim its own approved approval before acting |
| `GET /v1/whoami` | learn its own stable identity |

An agent may never resolve an approval, read the pending list, change
policy or execute anything. The identity used for authorization is the
credential's, never a field in a request body.

## 2. `POST /v1/runtime/check`

Request: a decision request (`resource-model.md` for the forms). Response:
`{decision_id, decision: allow|deny|escalate, reason_codes[], requires_approval, approval_id?, receipt_stub{policy_hash, action_digest}, matched_rule?, ...}`.

Rules every implementation keeps:

- The decision is made on the canonical resource, under the policy whose
  hash is returned.
- `nonce` and `issued_at` are checked: a replayed nonce or a stale request
  is refused.
- A request naming an agent identity other than the credential's is refused.
- The decision is recorded under `decision_id` for the provenance of an
  approval (§3): an approval can only be opened for a decision the gateway
  produced and escalated.

Reason codes a client may see (`reason_codes`): `allowed`, `policy_allow`,
`policy_deny`, `policy_escalate`, `trust_escalate`, `denied`, `escalate`,
`capability_expired`, `capability_not_allowed`, `capability_scope_mismatch`,
`capability_revoked`, `action_not_allowed`, `resource_not_covered`,
`missing_identity`, `identity_invalid`, `production_denied`, `trust_low`,
`trust_medium`, `anomaly_detected`, `containment_active`, `lease_required`,
`delegation_scope_mismatch`, `repeated_risk`, `risky_shell_pattern`,
`risky_git_pattern`, `production_target`, `weak_lease_scope`, `revoked`,
`revocation_unavailable`, `revocation_epoch_stale`. A client acts on the
decision; reasons are for people and receipts. New codes may be added.

### 2.1 `POST /v1/runtime/outcome` — `{decision_id, status, duration_ms?, error?}`

The caller says how the action went after acting on a decision (`status`
`ok` or `error`, the error's text for the latter, bounded to 600 bytes).
The gateway keeps it as an `action.outcome` event naming the decision, the
agent, the action and resource, so the decision and what happened share one
record. Reporting never changes a decision.

- `200 {decision_id, status, recorded}`.
- `404` for a decision the gateway never produced or no longer holds; `403`
  for another principal's decision (an operator may report any); `409` for
  a second report on the same decision, and for a decision that was
  **denied**: nothing was allowed to run, so the report is evidence of a
  caller that ignored the answer, and is kept as a `security.violation`
  event (`outcome_for_denied_decision`), as a foreign report is
  (`cross_principal_outcome`).

An SDK tool guard reports every call it ran; a harness of your own should
too. A missing outcome is not proof that nothing ran: the record of what
was *allowed* is the decision and its receipt.

## 3. Approvals

An approval is the gateway's own record of an escalated decision, shown to
a person. Its members: `approval_id`, `decision_id`, `action_type`,
`resource`, `environment`, `status` (`pending`, `approved`, `denied`;
`expired` is how a pending approval past its TTL reads), `created_at`,
`resolved_at`, `resolved_by`, `resumed_at`, `agent_id`, `reason`,
`context` (display only: query, body size, `body_sha256`, a redacted
preview; copied from the evaluated request, never from the caller),
`request_hash` (the digest of the evaluated request), `policy_version`.

### 3.1 `POST /v1/approval/create` — `{decision_id}`

- `201` with the approval when a new one is opened.
- `200` with an existing approval when the same agent already has one for
  the identical request: a **pending** one (same action type, environment,
  resource and context, which includes the body hash), or an **approved,
  unused** one answered within the pending TTL whose request digest is the
  same. A late answer is therefore not wasted: the identical request gets
  it back and claims it (§3.3).
- `404` for a decision the gateway never produced; `403` for another
  agent's decision; `429` past the per-agent cap on pending approvals (64,
  and four times that across one credential's named agents): the action
  stays blocked until approvals are resolved or expire.

### 3.2 `GET /v1/approval/{id}`

The approval. A foreign id answers `404` (its existence is not disclosed).

### 3.3 `POST /v1/approval/{id}/claim`

Marks an approved approval used, atomically in the store, so the action it
allows runs once. `200 {approval_id, status, claimed}`: the caller goes
ahead only when `claimed` is true; a pending, denied or expired approval is
reported as it is with `claimed` false. `409` when the approval was already
claimed: an identical request has to be asked again. `404` for a foreign or
unknown id.

### 3.4 Operator resolution

`POST /v1/approval/{id}/approve` and `/deny` (operator only). `resolved_by`
is derived from the credential. An approval pending longer than the TTL
(default 10 minutes, `approval_pending_ttl_secs`) can no longer be approved.

## 4. Stability

`/v1` is the contract. From specification 1.0 it never breaks: members are
added as optional, never removed or changed in meaning; reason codes and
statuses may be added; a change that needs more is `/v2`. Until 1.0,
changes are recorded in `CHANGELOG.md` under "Spec".

## 5. Tests that fix this contract

`runtime/gateway/internal/auth`: `TestRoleAgent_AllowedEndpoints`,
`TestRoleOperator_AllEndpointsAllowed`, the resolved-by tests;
`runtime/gateway/internal/handlers`: the identity red team (`TestRT*`:
foreign subjects, cross-agent create and get, replay, stale requests),
`TestClaim_IsSingleUseAndOwnerOnly`, `TestApprovalHandler_FloodControl`,
`TestApprovalHandler_ExpiredApproval`, the approval-context binding tests,
`TestOutcome_*` (the outcome report: owner or operator only, once, never
for a denied decision);
`runtime/gateway/internal/approval`: `TestOpen_*`, `TestClaim_*`;
`runtime/gateway/internal/models`: `spec_schema_test.go`;
`sdk/python/tests/test_guard.py` and `sdk/typescript/src/__tests__/guard.test.ts`
(the tool guards' use of this API against a stand-in gateway);
`tests/agents/harness.sh` (a custom harness against the API, 24 checks).

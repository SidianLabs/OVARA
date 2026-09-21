# OVARA 2.0 — P2.3.4 Revocation Implementation

Status: IMPLEMENTED — ready for independent adversarial security gate.
Not accepted. Acceptance belongs to the separate clean-room review.

Scope: durable revocation enforcement across issuer/gateway,
delegation/capability presentation, leases, approvals, continuations,
and execution claim-time authorization. P2.3.3 is untouched except for
one additive record kind in the shared journal fold.

## 1. Threat model

The adversary retains previously valid artifacts — leases, delegation
chains, approvals, queued continuations — and presents them after the
authority that created them has been killed. It can race revocation
against execution, replay old artifacts after restart, present
descendants of a revoked issuer, and (with filesystem access) modify,
truncate, or roll back local state. It cannot mint signatures for
trusted issuers and cannot write the operator's registry journal
through the agent token surface.

The property enforced:

> A previously valid authorization must not remain executable merely
> because it was issued before revocation.

## 2. Revocation authority model

Five revocation classes remain distinct and are never conflated:

| class            | target                          | kills                          |
|------------------|---------------------------------|--------------------------------|
| credential       | one credential (P2.2, existing) | that credential's auth         |
| identity         | suspend/retire (P2.2, existing) | all authorization for the id   |
| `issuer`         | issuer string                   | every hop + lease it signed    |
| `delegation`     | `sha256(lp(issuer)‖lp(nonce))`  | that presentation + descendants|
| `lease`          | `lease_id`                      | that lease's execution         |

`issuer`/`delegation`/`lease` are the new P2.3.4 classes. The
delegation target is byte-identical to the P2.1 replay identity —
one canonical name per presentation, no parallel key space.

**Authority boundary.** Revocation records are written only through
`gwidentity.Registry.Revoke` — i.e. write access to the domain
registry journal. Two surfaces reach it:

- `gwctl revoke --registry <file>` — operator file access (the same
  boundary as enrollment grants).
- `POST /v1/revocations` — operator-token-only HTTP route; the agent
  token surface never reaches it (403, tested).

The gateway process never self-authorizes a revocation; there is no
endpoint an agent can call. `POST /v1/capabilities/revoke` and
`revoke-by-subject` (operator-only) now write the journal FIRST and
treat it as the authoritative kill — the tracked-lease flag is
observability. A lease that was never tracked is still killable, and
a revocation is never reported that the execution boundary can't see.

## 3. Storage

`RevokeRecord` is an append-only journal line in the domain
`gwidentity` registry — `kind:"revoke"`, `class`, `target`, `actor`,
`reason`, `revoked_at`, `seq`, `chain`. It rides the existing
flock → append → fsync → hash-chain → anchor pipeline; no new
persistence model was introduced.

- `seq` IS the revocation epoch — monotonic with the journal.
- Revocations are permanent. There is no un-revoke record; a
  duplicate `Revoke` is a durable no-op that still advances seq.
- Journal fold indexes `revoked[class][target]`; `Revocations()`
  returns the audit list in seq order.
- The registry serializes all mutation under `r.mu`; readers fold a
  consistent absorbed view.

## 4. Epoch semantics

`Epoch()` returns the journal's current seq — every mutation (grant,
retire, revoke, rotate) advances it, so revocation state changes
always move the epoch forward. Properties:

- durable (journal fsync), monotonic (seq), regression-protected by
  the P2.3.3 hash chain + anchor when configured.
- `ActionRequest.min_epoch`: the caller cites the revocation view its
  authorization context requires. Checked BEFORE the request nonce is
  consumed — a stale gateway denies with `revocation_epoch_stale`
  without poisoning a retry under a fresher view. Missing checker or
  epoch error → `revocation_unavailable`. Both deny.
- `ReceiptStub.trust_epoch` / `Receipt.trust_epoch`: records which
  authority view produced the decision. Informational — NOT in the
  receipt HMAC preimage (existing signing semantics preserved).

## 5. Evaluation-time enforcement

`identity.Validator` gained a `revocation.Checker`; the evaluator's
`SetRevocation` pushes the same checker into whichever validator is
installed (order-independent).

Lease check order (§7 of the task): signature against the trusted
issuer key FIRST, then — only on cryptographically verified material —
one `AnyRevoked(issuer, lease_id)` query. Issuer revocation kills
every lease it signed; a revocation-state error yields an invalid
result (never "not revoked").

Delegation chains: every hop verifies (signature, linkage,
non-amplification, expiry, audience). For each verified hop the
validator collects `issuer` + `sha256(lp(issuer)‖lp(nonce))` targets
and evaluates them in ONE consistent absorbed view — a revocation
committed mid-validation is either fully visible or fully absent,
never torn across hops. The replay nonce is marked only after all
validation AND revocation checks pass — a forged or revoked
presentation cannot poison the replay cache.

## 6. Claim-time enforcement (the boundary that matters)

Approval creation captures authority identifiers from the
server-recorded decision request — never caller-supplied:
`lease_id`, terminal `delegation_key`, every hop `issuer`. They ride
the `Continuation` record.

`continuation.CheckClaimAuthority` runs AFTER the atomic claim wins
and BEFORE the executor is invoked, on both execution paths:

- orchestrator `executeOne` (queue drain), and
- synchronous `POST /v1/continuations/{id}/execute`.

Semantics — the linearization point is the claim:

| check result | effect |
|---|---|
| revoked      | terminal `denied`, no execution record, no side effect |
| unknown/err  | requeue to `queued` — UNKNOWN never becomes allow |
| clear        | executor invoked |

A later revocation is NOT retroactive to an execution that already
crossed the claim boundary — RVI-14 documents this honestly: the
system does not claim to stop an already-running external operation.

`handleResume` revalidates the approval's recorded identifiers
against current revocation state before the single-use resume token
is consumed — an approval cannot bypass revocation (RVI-07), and a
storage failure fails closed WITHOUT consuming the token.

## 7. Lease renewal

No lease renewal/extension endpoint exists in this codebase. A
"renewed" lease is a new artifact minted by the issuer — it must
validate (signature → revocation → scope) at eval like any lease.
TESTED: a fresh lease signed by a revoked issuer denies (e2e I2).
Re-issuance cannot resurrect authority because the issuer target, not
the lease, is dead.

## 8. Storage failure semantics

Every security-sensitive read returns `(state, error)` —
`AnyRevoked` surfaces errors; callers treat error as UNKNOWN and
UNKNOWN as deny/requeue. Never `error → allow`.

- corrupt record → hash-chain mismatch at load → gateway refuses boot
- torn tail (SIGKILL mid-append) → truncated at load, prior records
  intact, revocation state consistent
- journal write failure → `Revoke` errors; HTTP surface reports 500,
  no flag flips, no partial state
- epoch unavailable → `min_epoch` denies; `AnyRevoked` error → deny

## 9. Rollback protection

The revocation journal IS the P2.3.3 anchored journal — same file,
same chain. Anchored mode: a truncated/replaced journal diverges from
the oracle's monotonic tip → reconcile refuses boot (existing R16-R21
machinery, unchanged). Unanchored mode: the file is the authority and
an offline rollback is undetectable by design — TESTED and documented
as the residual bound (anchor required to bound rollback; P2.3.3
frozen semantics, not redesigned here).

In-process shrink (a live registry whose file loses tail records) is
detected by `absorbExternal` and rejected — the loaded view never
regresses below committed seqs.

## 10. Cross-gateway scope

One journal = one trust domain. Gateways sharing
`gateway_registry_file` (the P2.3.3 domain model) share revocation
state through the file: a revoke committed by one process is visible
to the other on its next absorbed read (TESTED: cross-process
visibility unit test + gwctl-write → gateway-read e2e). No claim of
cross-host distributed consistency is made — that is deferred.

## 11. Concurrency semantics

- `Registry` serializes mutation under `r.mu`; `Revoke` is atomic
  with the journal append.
- Claim is atomic (store `ClaimForExecution`); the revocation check
  runs inside the claim window on a consistent absorbed view.
- TESTED: 64 goroutines racing `ClaimForExecution`+`CheckClaimAuthority`
  against concurrent `Revoke` — every claim resolves to exactly
  denied or clean, no torn state, race detector clean.
- TESTED: concurrent registry `Revoke` from 32 goroutines — journal
  consistent, epoch monotonic, no lost records.

## 12. Historical receipts

Receipts are never rewritten. `trust_epoch` records the authority
view that produced the decision — a receipt for an execution that
passed the claim boundary before revocation remains valid historical
evidence (RVI-11). The receipt HMAC preimage is unchanged.

## 13. Replay independence (RVI-13)

Replay answers "was this presentation consumed?"; revocation answers
"is this authority still valid?". They share the presentation-key
identifier but are independent stores and checks. All four
combinations hold: unused+valid → allow; used+valid → replay deny;
unused+revoked → revocation deny (TESTED); used+revoked → deny.

## 14. Security invariants

| inv | statement | status |
|-----|-----------|--------|
| RVI-01 | revoked issuer cannot authorize new execution | TESTED |
| RVI-02 | issuer revocation invalidates descendants of its hops | TESTED |
| RVI-03 | presentation revoke spares sibling presentations | TESTED |
| RVI-04 | revoked lease cannot authorize execution | TESTED |
| RVI-05 | revoked capability/issuer cannot create a usable lease | TESTED (I2) |
| RVI-06 | queued continuations revalidated at claim-time | TESTED |
| RVI-07 | approval cannot bypass revocation | TESTED |
| RVI-08 | credential revocation distinct from identity revocation | TESTED (P2.2 suite green) |
| RVI-09 | storage failure cannot produce ALLOW | TESTED |
| RVI-10 | revocation state cannot silently roll back | TESTED w/ anchor; documented residual unanchored |
| RVI-11 | historical receipts not rewritten | TESTED (receipt sig tests green) |
| RVI-12 | unauthorized callers cannot create revocation | TESTED (agent 403 both routes; gwctl validates) |
| RVI-13 | replay and revocation independent | TESTED |
| RVI-14 | no false claim of retroactive stop | documented |
| RVI-15 | all execution-capable paths share the boundary | TESTED — two claim choke points + evaluator |

## 15. Test evidence

Unit:
- `gwidentity/revoke_test.go` — durability, idempotence, torn tail,
  corrupt record, rollback detect, epoch monotonicity, 32-way
  concurrent revoke, cross-process visibility.
- `identity/validator_revocation_test.go` — issuer kill, mid-chain
  descendant kill, sibling survival, storage-failure deny, lease kill,
  lease-from-revoked-issuer, replay independence, ChainRevocationIDs.
- `continuation/revocation_test.go` — queued-then-revoked, issuer
  kill, sibling survival, storage-failure requeue, no-authority
  pass, 64-way claim/revoke race.
- `evaluator/revocation_test.go` — min_epoch stale/satisfied/unknown/
  no-checker, receipt trust_epoch, lease revocation through journal.

E2E (`tests/e2e/p234_harness.py`, real binaries + real ed25519
artifacts): 39/39 — lease eval + claim denies, issuer revoke via HTTP
and gwctl, presentation granularity, multi-hop kill, min_epoch,
claim-time deny with zero execution records, terminal denied state,
resume gate, SIGKILL durability, corrupt journal boot refusal,
unanchored rollback semantics, agent-token 403s, gwctl validation.

Race detector: `go test -race ./internal/... ./pkg/...` clean.
Full suite: `go test ./...` green.

Frozen regression (all green, no rewrites):
RC1 46/46, P2.1 7/7, P2.2 21/21, P2.2-gate 37/37, P2.3.1 22/22,
P2.3.2 35/35, P2.3.3 65/65.

## 16. Known limitations (honest)

- ASSUMED: unanchored mode cannot detect offline journal rollback —
  the file is the authority. Anchoring (P2.3.3) bounds this; without
  it, an attacker with file write can regress the epoch.
- ASSUMED: filesystem write access to the registry journal IS the
  revocation authority boundary — same trust assumption as
  enrollment grants.
- DEFERRED: cross-host revocation propagation (same-domain shared
  file only); remote kill of already-running executions (RVI-14 —
  never claimed); TPM-backed revocation keys; multi-domain
  revocation.
- INFORMATIONAL: `trust_epoch` is advisory — receipts don't sign it.
- INFORMATIONAL: `AnyRevoked` is O(#targets) map reads on a folded
  view; no scanning cost per request.

## 17. Changed files (P2.3.4 delta)

- `internal/gwidentity/store.go`, `chain.go` — RevokeRecord, fold,
  Revoke/IsRevoked/AnyRevoked/Epoch/Revocations.
- `internal/revocation/types.go` (new) — Class, Pair, Checker,
  PairsFor.
- `internal/identity/validator.go` — revocation checks on verified
  material, ChainRevocationIDs.
- `internal/evaluator/evaluator.go` — min_epoch gate, SetRevocation,
  trust_epoch.
- `internal/models/{action_request,decision_response}.go` — MinEpoch,
  TrustEpoch fields (additive, omitempty).
- `internal/continuation/{store,orchestrator,revocation}.go` —
  authority ids on Continuation, CheckClaimAuthority, claim-time gate.
- `internal/handlers/{continuations,approval,capabilities,revocations}.go`
  — sync-execute gate, resume gate, journal-authoritative capability
  revoke, operator revocation API.
- `internal/approval/models.go` + `handlers/approval.go` — authority
  capture at creation.
- `pkg/server/server.go` — one registry-backed checker to every
  consumer.
- `cmd/gwctl/main.go` — `revoke`, `revocations`, `epoch`.
- `tests/e2e/p234_harness.py` (new).
- `internal/{gwidentity,identity,continuation,evaluator}/*_test.go`.

P2.3.3 was not redesigned; its only delta is the additive
`kind:"revoke"` case in the shared journal fold + chain sealing.

# OVARA 2.0 — P2 Trust & Lifecycle Design Spec

Status: DESIGN ONLY. No implementation. RC1
(`17649ac6fc36a25a0a2ec297f2e4ebeef8008bb5`) is the frozen baseline and
must not be weakened. Where this spec has a genuine open choice it
defers to `OVARA_P2_SECURITY_DECISIONS.md` rather than silently
choosing.

## 1. Executive summary

RC1 proves one thing well: a single request crossing a single gateway
is correctly authorized, evidence is tamper-evident, and the whole
chain fails closed. What RC1 cannot do is survive *time*: tokens never
expire, identity dies with its credential, replay protection evaporates
on restart, only leases can be revoked, receipts have no external
anchor, network containment is asserted for one tested configuration,
and nothing watches Ovara itself.

P2 adds the lifecycle layer: stable identity independent of
credentials, credential issue/rotate/revoke, durable replay state,
runtime revocation with bounded propagation, external receipt
anchoring, verified network containment, and an integrity monitor that
does not trust Ovara.

The recurring design principle: **every P2 mechanism is state, and
state must have an owner, a freshness rule, and a failure mode.**
This spec is organized around those three questions for each subsystem.

## 2. RC1 limitations being addressed

| Limitation | RC1 status | P2 section |
|---|---|---|
| Tokens static, no expiry/rotation/revocation | DEFERRED | §7 |
| Identity = credential hash | DEFERRED | §6 |
| Replay: in-memory, 5-min, process-local | ARCHITECTURAL LIMITATION | §8 |
| Revocation: leases only | PARTIAL | §9 |
| Anchoring: local stubs only | ARCHITECTURAL LIMITATION | §11 |
| Network containment: tested config only | scoped claim | §12 |
| No integrity monitor | I8 unbuilt | §13 |
| No multi-gateway story | single-tenant | §15 |

## 3. Design goals

- **G1**: no P2 mechanism weakens an RC1 invariant (listed §21).
- **G2**: fail closed on every new state dependency unless an explicit
  documented degraded mode exists — and degraded ≠ allow.
- **G3**: every new trust root ships with owner, rotation, revocation,
  and blast-radius answers before it is adopted.
- **G4**: availability of anchoring/monitoring never gates the data
  plane — but authorization-critical state (replay, revocation) fails
  toward deny/escalate, never toward allow.
- **G5**: single-gateway deployment must remain fully functional;
  multi-gateway is an explicit upgrade path, not a requirement.
- **G6**: P2 is additive — RC1 requests/wire formats continue to work
  through a documented migration window.

## 4. Non-goals

- Multi-tenant SaaS control plane (P2 stays single-tenant/deployable;
  multi-gateway is in-scope, multi-tenant is not)
- Host/kernel compromise defense (A7 stands)
- Replacing RC1's cryptographic primitives (ed25519, HMAC-SHA256,
  canonical LP encoding stay)
- Content-level exfiltration prevention (still UNPROTECTED by design)
- Real-time revocation at wire speed (bounded staleness is accepted)

## 5. Trust architecture

```text
                    ┌──────────────────────────────┐
                    │      GOVERNANCE (human)       │
                    └──────────────┬───────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
┌───────▼───────┐        ┌────────▼────────┐        ┌─────────▼────────┐
│ TRUSTED       │        │ REVOCATION      │        │ IDENTITY         │
│ ISSUERS       │        │ AUTHORITY       │        │ REGISTRY         │
│ (delegation/  │        │ (signed         │        │ (credential ↔    │
│  lease sigs)  │        │  statements)    │        │  stable-id map)  │
└───────┬───────┘        └────────┬────────┘        └─────────┬────────┘
        │                         │                           │
        ▼                         ▼                           ▼
        └───────────►  GATEWAY EVALUATOR  ◄────────────────────┘
                            │   checks: identity, delegation, lease,
                            │   revocation, replay (durable), policy
                            ▼
                     DECISION → APPROVAL → EXECUTION
                            │
                            ▼
                     RECEIPT CHAIN ──► CHECKPOINT ──► EXTERNAL ANCHOR
                            ▲
              INTEGRITY MONITOR (external trust) watches all of it
```

Trust roots (each gets the full 11-question treatment before adoption):
operator config, external issuer keys, registry signing key, credential
issuer, revocation signing key, anchor service key, monitor trust
anchor.

## 6. Identity architecture

### 6.1 The separation

RC1: `identity = f(credential)`. P2 introduces a stable identity:

```
AGENT_IDENTITY (stable, registry-issued, survives rotation)
        ▲ binds (n:m over time, 1:1 at a time)
CREDENTIAL (rotatable, revocable, expirable)
        ▲ derives (unchanged RC1 rule)
PRINCIPAL (per-request, from the presented credential)
```

**RC1-compatible rule preserved**: the presented credential still
determines the request principal — what changes is what the principal
*maps to*. A revoked/expired credential maps to nothing → deny. An
unmapped credential maps to nothing → deny (or legacy mode, §17).

### 6.2 Invariants the new system must preserve (before designing)

- An attacker with a stolen credential can only claim the identity
  that credential is bound to — binding is registry-signed.
- Identity substitution (binding your credential to my identity)
  requires registry authority.
- A revoked credential stops authenticating within propagation bound.
- An unregistered identity cannot authenticate at all (fail closed).
- The registry itself is a trust root: compromise = mint/rebind
  identities — must be governable, auditable, revocable.

### 6.3 Identity lifecycle

```
REGISTERED ──► ACTIVE ──► SUSPENDED ──► ACTIVE
                 │            │
                 ▼            ▼
              MIGRATED     RETIRED (terminal, tombstoned)
```

- REGISTERED: identity record created, no usable credential yet
- ACTIVE: ≥1 valid credential bound
- SUSPENDED: identity intact, all auth denied (admin action)
- MIGRATED: supplanted by a successor identity (rename/merge path)
- RETIRED: terminal tombstone — prevents re-registration squatting
  (re-registering a retired ID must not silently restore history)

### 6.4 Threats addressed

- Identity theft → binding is registry-signed, not self-asserted
- Stale credentials → generation/expiry checks
- Replayed registration → registry serializes writes
- Malicious re-registration → tombstones + operator approval path
- Unauthorized credential attachment → binds require identity-owner
  or operator authorization, both logged

## 7. Credential lifecycle

### 7.1 What a credential is

A bearer secret that authenticates a request *as* a bound identity.
In RC1 terms: `agent_tokens[]` entries. In P2: issued artifacts with
metadata — `cred_id`, `identity_id`, `issuer`, `issued_at`,
`expires_at`, `generation`, `status`, optional `not_before`.

### 7.2 State machine

```
ISSUED ──► ACTIVE ──► EXPIRED (auto, terminal)
   │          │
   │          ├──► ROTATING (grace window, both valid, bounded)
   │          │        └──► SUPERSEDED (terminal)
   │          ├──► REVOKED (admin/compromise, terminal)
   │          └──► SUSPENDED (identity suspended)
   └──► DESTROYED (never activated — issuance aborted)
```

Key semantic: **ROTATING is the only state where two credentials for
one identity are both valid**, and it is strictly time-bounded
(default recommendation: minutes-to-hours, not days). SUPERSEDED
credentials deny immediately.

### 7.3 Answers to the required questions

- A credential authenticates the *binding*: "this bearer may act as
  identity X" — nothing more.
- Rotation: old cred enters ROTATING (grace), then SUPERSEDED. Same
  identity continues.
- Invalidation: revocation store entry + generation counter;
  enforcement checks `cred.generation == identity.generation` or
  `status != ACTIVE/ROTATING` → deny.
- Propagation: bounded staleness (see §9.3); enforcement points may
  cache negative-valid results only.
- Gateway restart: durable credential store survives; in-flight
  ROTATING windows continue (time-based, not session-based).
- Partition: bounded staleness; after budget expiry → escalate, not
  allow (DECISION-03).
- Storage unavailable: identity-derivation itself unaffected (it's
  a hash); *validity* checks degrade to deny/escalate — never allow.
- Stolen cred after rotation: SUPERSEDED → useless.
- Replayed old credential: generation check kills it.
- Revoked cred creating delegations: delegation validation requires
  terminal subject = principal of a *valid* credential → blocked.
- Revoked cred using existing chains/leases: chains are capabilities
  bound to the *subject*; if subject's credential is revoked the
  request itself fails authentication before chain validation.
- Cross-agent boundary: credential theft compromises only the bound
  identity — isolation is per-identity.

### 7.4 Fail mode

Validity-store unreachable → deny (cannot prove valid). This is the
hardest operational choice: it trades availability for correctness.
DECISION-02 records the degraded-read alternative.

## 8. Replay architecture

### 8.1 The security property (formal)

> **Within the lifetime of a capability artifact (min of expiry and
> revocation), a given replay identifier may produce at most one
> allow-type decision across the trust domain — restarts, crashes,
> and (where deployed) replicas notwithstanding.**

Note the scoping: the property covers *allow-type decisions*, not
executions — because policy/lease may still deny. And "trust domain"
bounds the multi-instance claim (§15).

### 8.2 Replay identifier

RC1: `sha256(lp(issuer)‖lp(nonce))` for delegations; raw nonce for
requests. P2 generalizes to a **presentation ID**:

```
pid = sha256( lp(artifact_type) ‖ lp(issuer) ‖ lp(subject)
            ‖ lp(terminal_nonce) ‖ lp(artifact_id?) )
```

Artifact-scoped, collision-free by length-prefixing, same derivation
rule as RC1 (no format break needed for delegation nonces).

### 8.3 Atomic consume

The mark must be atomic with the *decision commit* — a presentation
is consumed when its decision is committed, not when validation starts
(RC1 already orders mark-after-validate; P2 adds durability):

```
BEGIN; INSERT pid IF NOT EXISTS (owner=decision_id, ts, ttl);
COMMIT → first presenter wins; others see CONSUMED → deny replay.
```

### 8.4 Threat answers

- Restart/crash: durable store → consumed stays consumed.
- Concurrent presentations: single-writer or compare-and-insert →
  one wins.
- Clock skew: TTL is relative-to-store-clock, not requester clock.
- Network retries/duplicate delivery: same pid → consumed → deny
  (idempotent replays of a *legitimate* retry get deny too — client
  must re-request with fresh nonce; acceptable: replays are attacks
  by definition here).
- DB rollback (backup restore): consumed pids can resurrect → this is
  exactly why anchoring matters (§11): restore-vs-anchor divergence
  detects rollback. Mitigation: store includes a high-watermark
  checkpoint; post-restore, pids older than last anchored head are
  re-marked suspect → escalate (not deny — restored state is
  ambiguous).
- Split brain (two gateways, separate stores): each accepts pid once
  → capability double-spend. Requires either a shared store, a
  single-authority-per-domain rule, or federation of consumed pids
  (DECISION-04).
- Replication delay: consumed-in-A not yet visible at B → bounded
  staleness; same answer class as revocation.

### 8.5 Storage choices

See DECISION-04: (a) embedded durable store (sqlite/rocksdb, atomic),
(b) external store (postgres/redis with CAS), (c) single-authority
model (one gateway = the replay authority; replicas forward checks).
Single-gateway deployments keep full strength with (a); (b)/(c) are
for clusters.

## 9. Revocation architecture

### 9.1 What can be revoked

| Artifact | Revocation identity | Mechanism |
|---|---|---|
| Credential | cred_id | Revocation store entry |
| Identity | identity_id | Registry status → SUSPENDED/RETIRED |
| Issuer | issuer_id | trusted_issuers removal + signed revocation statement |
| Delegation chain | chain_id / terminal nonce | Revocation store (artifact-level) |
| Lease | lease_id | EXISTS (RC1: RevokedAt) — extend to shared model |
| Approval/continuation | decision_id | Exists via deny-is-terminal |

### 9.2 Recommended model (subject to DECISION-05)

**Signed revocation statements + generation epochs, pulled with a
staleness budget**:

- Revocation authority signs statements: `{artifact_class, id,
  revoked_at, epoch, signature}`.
- Gateways pull + cache for `staleness_budget` (recommend 30–120s).
- Check order in evaluator: revocation check BEFORE accepting an
  artifact as valid — after cryptographic validity (a forged artifact
  needn't consult revocation).
- Epoch: a monotonically increasing domain counter; a request can
  cite `min_epoch` — gateways below it deny/escalate.

Why not pure denylist: unbounded growth and no freshness proof. Why
not pure short-TTL: latency vs operational cost trade-off — TTL is
the floor, statements handle immediate kills. The combination is
deliberately boring and matches lease revocation's existing shape.

### 9.3 Staleness semantics

```
age(cached_revocation_view) ≤ staleness_budget → enforce normally
age > budget → dependent artifacts degrade:
    delegation/lease-bearing requests → escalate (human checks)
    plain requests → continue (revocation protects capabilities,
                    not base auth — see DECISION-03 whether this
                    boundary is acceptable)
```

### 9.4 The A→B→C revocation question

If issuer A is revoked (statement against issuer_id A):

- **A→B hop**: invalid going forward — A's signature no longer
  verifies (issuer removed from registry / revocation checked first).
- **B→C hop**: a chain is only valid if EVERY hop verifies —
  A revoked ⇒ the A→B→C chain dies entirely (root invalid ⇒ all
  descendants invalid).
- **Existing leases from A**: revoked if issued by A (issuer-level
  statement covers them) or subject-level if specified.
- **Previously issued approvals**: already-committed approvals are
  historical records — revocation does not rewrite history; it does
  block *execution* of pending continuations (execution-time check).
- **Running executions**: not retroactively killed (out of scope —
  documented); pending queued continuations check revocation at
  execution time.
- **Future requests**: fail at issuer verification → deny.
- **Child delegation already issued by B to C**: dies with the root —
  there is no orphan-validity semantics.

## 10. Delegation lifecycle

Unchanged semantics (RC1 frozen). P2 adds lifecycle metadata only:

- `chain_id` (issuer-assigned, part of signed payload — enables
  artifact-level revocation without breaking linkage)
- optional `not_before`
- revocation check in the validation order (§9.4)

No new delegation semantics, no field removal, no weakening of
non-amplification, terminal-subject binding, or audience rules. The
empty-audience semantic (unscoped, any gateway) is **carried forward
deliberately** — it is a documented issuer choice, and revocation +
audience remain the tools to bound it.

## 11. Receipt anchoring

### 11.1 What anchoring must prove — and what it must not claim

Distinguish precisely:

- **INTEGRITY**: receipt bytes unchanged since receipt — ALREADY
  covered by signature+chain (RC1).
- **ORDERING**: receipt N preceded N+1 — covered by hash chain.
- **EXISTENCE-at-T**: a checkpoint existed at time T — this is what an
  external anchor adds (the anchor's signature over {head_hash, T}
  witnessed by a party Ovara doesn't control).
- **COMPLETENESS**: no receipts were *omitted* — anchoring does NOT
  prove this; a missing receipt is invisible. Mitigated by I3
  (record-failure = CRITICAL) + gap detection in sequence IDs, but
  completeness is fundamentally unprovable for unwritten events.
- **EXECUTION**: that the action really ran — anchoring does NOT prove
  this; receipts attest a decision path was evaluated and recorded,
  not that a downstream effect occurred. Do not claim it.

**Anchor claim (correctly scoped)**: *"the receipt-chain head recorded
at time T is the head that existed at time T — rewriting or deleting
anchored history afterwards produces a verifiable divergence."*

### 11.2 Architecture

```
receipt ──► local hash chain (exists)
   every N receipts (or T interval):
   head = H(chain) ──► CHECKPOINT {head, index, gw_id, ts, prev_checkpoint}
                        │
                        ├─ local anchors.jsonl (exists today)
                        └─► external anchor service:
                            stores (gw_id, index, head, ts),
                            signs + returns attestation,
                            enforces append-only per (gw_id,index):
                            a second head at same index = fork = ALERT
```

Verification: recompute chain → compare heads → confirm anchor
attestations → any anchored prefix that diverges from current chain =
tamper detected. Fork at an index = two histories claimed = alarm.

### 11.3 Options (DECISION-06)

- **O1 append-only remote service** (simplest): endpoint stores
  checkpoints, rejects index conflicts. Trust: the service is honest
  about append-only. Works today-ish with `anchor_url` stub.
- **O2 Merkle transparency log**: checkpoints become tree leaves;
  inclusion proofs per receipt. Stronger evidence, real complexity.
- **O3 periodic signed checkpoints to object storage** (S3/immutable
  bucket): durability + immutability-by-policy, no live service.

O1 is the honest minimum viable anchor and matches existing stubs.
O2/O3 are escalation paths, not blockers.

### 11.4 Threat answers

- Local deletion/rewrite post-anchor → head mismatch at verify →
  detected.
- Forked history → index conflict at anchor → alert.
- Compromised gateway pre-anchor → it can fabricate receipts it then
  anchors — anchoring detects *post-anchor* rewrite, not
  *pre-anchor* fabrication (honest scoping: anchor ≠ truth oracle).
- Anchor unavailable → queue locally, flag unanchored; transit never
  blocks (G4).
- Compromised anchor → it can suppress or fork; mitigations are
  quorum/multi-anchor or operator-held checkpoint copies — DECISION-06.

## 12. Network containment model

### 12.1 The claim and what must be true

Claim being designed for: *"the agent cannot reach an unauthorized
external resource without transiting the enforcement boundary."*

For that to be true, EVERY one of these must hold:

| # | Requirement | Class |
|---|---|---|
| N1 | Agent cannot open a socket to non-proxy destinations | architectural (netns/nft) |
| N2 | Agent cannot influence routing/DNS to redirect around proxy | capability absence + monitor |
| N3 | Agent cannot use another interface/namespace as egress | kernel/container assumption |
| N4 | Proxy itself enforces destination+policy (RC1 ✓) | verified |
| N5 | No alternate local IPC yields external reach (unix sockets to a forwarding helper) | configuration-dependent |
| N6 | Agent cannot mint raw/ICMP/other-protocol packets | capability absence (A2) |
| N7 | Redirect/upgrade paths can't launder egress | proxy strips + re-checks |

### 12.2 Verification model (not implementation)

- **Boundary test suite** as first-class CI: matrix of
  channel × transport × target (exists partially in
  `tests/boundary/`); each cell asserted BLOCKED/CONTROLLED/
  UNPROTECTED — and unprotected cells must be *declared*, not
  silently open.
- **Doctor asserts preconditions live** (A1–A6 today) → extend to
  N1–N7 checks: nft ruleset hash, interface count, capability
  bounding set, unix-socket inventory, resolver path.
- **Runtime monitor** (I8) watches the boundary invariants:
  interface appears → violation; route changes → violation; new
  listener socket by agent → signal.

### 12.3 Honest scoping

N3 and parts of N6 are kernel/container assumptions — same class as
A7. The claim is always qualified: *under the tested containment
configuration with the declared capability bounding set*.

## 13. Integrity monitor (I8)

### 13.1 The watcher problem

If Ovara monitors Ovara, compromise covers both. The monitor's
trust anchor MUST live outside Ovara's runtime — else I8 is theater.

### 13.2 Trust placement options (DECISION-07)

- **M1 external watchdog process** — separate binary, separate
  credentials, host-level (not agent-level) privileges; measures
  files/state and reports out-of-band. Its own compromise is a host
  problem (A6/A7-adjacent).
- **M2 measured/attested boot (TPM)** — kernel measurements into a
  TPM; verifier compares. Strongest, hardware-dependent.
- **M3 remote attestation service** — periodic signed self-reports
  verified externally; dead-man timer catches monitor death.

M1 is the pragmatic floor: an independent process the agent cannot
ptrace/write (capability + uid separation), reporting to an endpoint
the agent cannot reach (different egress path or operator-held).

### 13.3 What it measures

- Binary + config + policy file hashes vs signed manifest
- Receipt-chain head vs anchor attestations (state tampering)
- Boundary invariants: interface/route/resolver/capability sets
- Process integrity: no ptrace on gateway/proxy, expected owners
- Its own liveness → dead-man alert if reports stop

### 13.4 Response semantics

Detection ≠ prevention: on tamper, monitor signals CONTAINMENT LOST +
operator alert; it cannot un-compromise, it can only make silence
impossible. Honest I8 language: *detect*, never *prevent*.

## 14. Persistence model

| State | Owner | Store | Freshness rule | Failure mode |
|---|---|---|---|---|
| Identity registry | Registry service | Its own DB | Authoritative | Down → deny-or-degrade per DECISION-02 |
| Credential validity | Registry | Its own DB | staleness_budget | Down → deny |
| Revocation statements | Revocation authority | Signed, replicable | staleness_budget | Stale → escalate; unavailable → bounded-degrade |
| Replay consume | Gateway (or shared) | Durable, atomic | Atomic | Down → deny |
| Receipts | Proxy/gateway | File chain | Append-only | Record-failure → CRITICAL |
| Anchors | Anchor service | Its own log | n/a | Down → queue+flag |
| Monitor reports | Monitor | External sink | n/a | Dead-man alert |

Rule: every state has exactly one owner; readers hold caches with
explicit staleness budgets, never ambiguous freshness.

## 15. Multi-gateway model

Two deployment classes, deliberately separated:

- **Single gateway**: full P2 strength trivially (one writer, one
  replay store, one revocation view). Target for most deployments.
- **Clustered gateways**: requires a consistency model — shared
  store (linearizable, SPOF) or authority-per-domain (each domain
  has exactly ONE gateway authorized to mint allow-decisions for
  its capabilities — replay scoped to domain). DECISION-04.

Split-brain is the enemy: two independent gateways sharing a trust
domain can each allow the same capability once. Mitigations: domain-
scoped capability issuance (audience-bound, which exists), or a
shared consume store. Audience binding already provides the natural
domain boundary — **a capability presented to the wrong gateway is
denied today**; the open question is only same-domain replicas.

## 16. Failure semantics (summary table)

| Component down | Behavior |
|---|---|
| Identity registry | deny identity-bound requests (or degrade per DECISION-02) |
| Revocation view stale > budget | capability-bearing → escalate; base auth per DECISION-03 |
| Replay store | deny (cannot prove non-replay) |
| Anchor | queue + flag; never block |
| Monitor | dead-man alert |
| Backup restored | reconcile vs anchors; suspect-window → escalate |

Default everywhere: **fail toward deny/escalate, never toward allow.**

## 17. Migration strategy

```
RC1 (frozen) ──► P2-COEXIST ──► P2-ENFORCED
```

- **P2-COEXIST**: P2 stores exist; RC1 behaviors continue for
  unregistered artifacts. New fields optional. `legacy_mode=true`
  documented flag: unmapped credentials still derive principals
  (RC1 semantics) — operator-visible warning, bounded window.
- **P2-ENFORCED**: `legacy_mode=false`; unmapped credentials deny.
  Migration completes per deployment.

Compatibility:
- Existing credentials → import into registry as ACTIVE bindings
- Existing principals → become identity IDs directly (they're already
  stable strings; the registry just makes them survive rotation)
- Existing chains/leases → remain valid; chain_id optional so old
  artifacts validate (revocation by subject/issuer still covers them)
- Existing receipts → chain continues; anchoring starts at next
  checkpoint (no re-anchoring of history needed — honest: pre-anchor
  history stays locally-attested only)
- SDK → canon unchanged; client gains optional identity/credential
  fields — old clients keep working
- Wire format → additive fields only, no removals

## 18. Compatibility

| Interface | Guarantee |
|---|---|
| `/v1/runtime/check` request | additive optional fields only |
| Delegation wire format | unchanged (chain_id optional) |
| Lease wire format | unchanged |
| SDK canon vectors | unchanged — new vectors additive |
| Policy file format | unchanged |
| Receipt format | checkpoint fields additive |
| Config | additive keys; new stores default in-memory+warn |

## 19. Observability

New events: `credential.issued/rotated/revoked`,
`identity.registered/suspended/retired/rebound`,
`revocation.statement.applied/stale`,
`replay.consumed/duplicate/rejected`,
`anchor.checkpoint/fork_detected/unavailable`,
`monitor.tamper/liveness_lost`,
`rollback.detected` (restore reconciliation).

All security-relevant state transitions emit events — P2's attack
surface is largely state transitions.

## 20. Testing strategy

- Extend `tests/e2e/rc1_harness.py` stages: credential lifecycle
  (issue→rotate→stale-deny→revoke→recovery), registry binding
  (substitution→deny), durable replay (restart→deny, crash mid-mark
  → consistent), revocation propagation (revoke→deny within budget,
  stale→escalate), anchoring (rewrite→divergence-detected, fork→alert),
  monitor (tamper→detected, dead-man→alert), multi-gateway
  (split-brain→single-consume where deployed).
- Property tests: replay-at-most-once under concurrency; revocation
  monotonicity (never un-revokes); anchor divergence always detectable.
- Rollback drills: backup-restore then assert suspect-window behavior.
- The RC1 46/46 suite must keep passing unchanged — the migration
  contract is executable.

## 21. Security invariants (P2 matrix)

| # | Invariant | Property | Threat | Trust assumption | Enforcement | Verification | Failure mode |
|---|---|---|---|---|---|---|---|
| I1 | Identity authenticity | only registry-bound identities authenticate | forged identity | registry trusted | middleware+registry | sub attempt → deny | deny |
| I2 | Identity stability | principal survives rotation | identity loss on rotate | registry binding | registry+cred check | rotate→same-id auth | n/a |
| I3 | Credential revocation | revoked cred can't auth post-propagation | stolen cred | staleness bound | validity check | revoke→deny | stale→escalate |
| I4 | Non-amplification | unchanged (RC1) | escalation via child | — | validator | RC1 suite | deny |
| I5 | Delegation authenticity | unchanged (RC1) | forged chain | issuer keys | validator | RC1 suite | deny |
| I6 | Audience binding | unchanged (RC1) | cross-gateway replay | gw identity | validator | RC1 suite | deny |
| I7 | Capability/request binding | unchanged (RC1) | cap used for wrong req | — | evaluator | RC1 suite | deny |
| I8 | Lease enforcement | unchanged (RC1) | wrong subj/aud/scope | issuer keys | evaluator | RC1 suite | deny |
| I9 | Policy enforcement | unchanged (RC1) | bypass | policy store | evaluator | RC1 suite | deny |
| I10 | Approval integrity | unchanged (RC1) | substitution | server binding | handlers | RC1 suite | deny |
| I11 | Durable replay | at-most-once per artifact lifetime | restart/split-brain replay | store atomicity+ownership | consume store | restart/concurrency tests | deny |
| I12 | Credential confidentiality | custody (RC1) + no stale re-use | theft | proxy boundary | proxy+cred store | e2e + stale-deny | deny |
| I13 | Evidence integrity | unchanged (RC1) | tamper | signing keys | chain+sig | verify+tamper-test | detect |
| I14 | Evidence anchoring | post-anchor rewrite detectable | history rewrite | anchor honesty (scoped) | checkpoints | rewrite→divergence | flag, not block |
| I15 | Network containment | no unbounded egress under tested config | bypass | kernel/caps (A-class) | netns/nft+monitor | boundary suite | violation event |
| I16 | Boundary integrity | modification detectable by external party | binary/config/state tamper | monitor independence | monitor | tamper drill | alert |
| I17 | Cross-agent isolation | one identity's creds never auth another | cred theft | binding | middleware | cross-bind attempt | deny |
| I18 | Cross-tenant isolation | out of P2 scope (single-tenant) | — | deployment | n/a | n/a | documented |
| I19 | Fail closed | every new dependency defaults deny | any failure | — | all | failure drills | deny/escalate |
| I20 | Revocation propagation | bounded staleness, degrade-toward-safe | suppression | time-bound | epoch+budget | revoke→deny within T | escalate |

## 22. Threat coverage

All T-* threats from the threat model map to at least one invariant
and one control; T-REGISTRY-TAKEOVER and T-ENROLL-CLONE are flagged
as open (registry is a new root; enrollment-clone needs gateway
identity keys — a real P2 addition worth its own decision entry).

## 23. Open design decisions

Tracked in `OVARA_P2_SECURITY_DECISIONS.md`:

- D-01 identity registry: embedded vs service
- D-02 credential validity check: strict-deny vs degraded-read
- D-03 revocation staleness: escalate vs deny for capability requests
- D-04 replay store: embedded vs shared vs single-authority
- D-05 revocation model: statements+epochs vs denylist vs pure-TTL
- D-06 anchor model: append-only service vs Merkle log vs object store
- D-07 monitor placement: watchdog vs TPM vs remote attestation
- D-08 gateway identity: keys vs ID-only (enrollment-clone defense)
- D-09 registry+issuer co-location: same service or separated
- D-10 staleness budget values

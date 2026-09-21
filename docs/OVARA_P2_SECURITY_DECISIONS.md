# OVARA 2.0 — P2 Security Decision Record

Design-only companion to `OVARA_P2_TRUST_LIFECYCLE_DESIGN.md`. Every
unresolved architectural choice is recorded here; nothing is silently
decided. Status values: `OPEN`, `LEANS` (recommendation stated,
not ratified), `REQUIRED-BY-INVARIANT` (only one option preserves an
invariant).

---

## D-01 Identity registry placement

- **Question**: embedded in the gateway, or a separate service?
- **Options**:
  - (a) Embedded store inside the gateway (like enrollment.json today)
  - (b) Standalone registry service (HTTPS, signed responses)
  - (c) Registry as part of the (optional) control plane
- **Security consequences**: (a) registry inherits gateway compromise —
  whoever owns the gateway owns identity binding; weakest root
  separation. (b) real trust root with its own keys — stronger
  separation, new attack surface. (c) concentrates trust in control
  plane — supply-chain class blast radius.
- **Operational consequences**: (a) zero new infrastructure — best for
  small deployments; (b) new service to run/monitor; (c) only viable
  where a control plane already exists.
- **Recommendation**: (a) for single-gateway deployments — a separate
  service adds a network hop to the auth path; (b) when clustering.
  Do not couple to control plane unless one already exists.
- **Rationale**: ponytail — no new service for the common deployment;
  the boundary that matters is agent↔gateway, already enforced.
- **Status**: LEANS (a) single / (b) cluster — OPEN.

## D-02 Credential validity check failure mode

- **Question**: when the credential/identity validity store is
  unreachable, deny or degrade?
- **Options**: (a) strict deny; (b) degraded-read (cached last-known
  validity for bounded window, then deny).
- **Security consequences**: (a) availability loss = outage; zero
  stale-auth risk. (b) bounded stale-auth window — a revoked cred
  works until cache expiry.
- **Operational consequences**: (b) survives store hiccups; (a)
  simplest to reason about, hardest on ops.
- **Recommendation**: (b) with a SHORT bound (seconds–minutes) for
  *validity* reads specifically — this is liveness, not revocation
  (revocation uses signed statements with their own budget, D-03).
- **Rationale**: availability vs correctness trade-off; a bounded
  cache is strictly better than deny-all for registry hiccups while
  still bounded in staleness.
- **Status**: LEANS (b) — OPEN.

## D-03 Revocation staleness degrade action

- **Question**: capability-bearing requests arriving when the
  revocation view exceeds its staleness budget — escalate or deny?
- **Options**: (a) escalate (human); (b) deny; (c) allow with
  unrevoked-assumption.
- **Security consequences**: (c) is a silent hole — suppressing
  revocation propagates access. (a) preserves a manual escape hatch.
  (b) hardest guarantee.
- **Operational consequences**: (b) can mass-deny during a control-
  plane outage; (a) needs operators present.
- **Recommendation**: (a) escalate — consistent with Ovara's existing
  trust-violation semantics (uncertain → human, not silent).
  **Never (c).**
- **Rationale**: matches RC1's escalate-on-suspicion philosophy.
- **Status**: LEANS (a) — OPEN. (c) rejected outright.

## D-04 Replay store architecture

- **Question**: how is the consume-record stored, and how do multiple
  gateways coordinate?
- **Options**: (a) embedded durable store per gateway (sqlite/
  bbolt, atomic CAS); (b) shared external store (postgres/redis,
  linearizable); (c) single-authority: exactly one gateway per trust
  domain consumes; replicas forward.
- **Security consequences**: (a) split-brain capable — two gateways,
  two consumes of one capability (I11 broken cross-instance).
  (b) linearizable → at-most-once holds cluster-wide, SPOF.
  (c) strongest per-domain guarantee, forces routing discipline.
- **Operational consequences**: (a) zero deps; (b) external infra;
  (c) constrains deployment topology.
- **Recommendation**: (a) for single-gateway (which fully satisfies
  I11 within its domain); for clusters, (c) is the cleaner security
  story — audience binding already scopes capabilities to a domain.
  (b) only where a HA store already exists.
- **Rationale**: don't build distributed consensus for deployments
  that are one process; make the domain boundary do the work.
- **Status**: LEANS (a)+(c) — OPEN.

## D-05 Revocation model

- **Question**: statements+epochs, pure denylist, or pure short-TTL?
- **Options**: (a) signed statements + epoch counter + staleness
  budget; (b) replicated denylist; (c) no revocation — capabilities
  just short-lived.
- **Security consequences**: (a) freshness-provable, revocable,
  auditable. (b) unbounded growth, no freshness. (c) simplest, but
  "revoke NOW" impossible — latency = TTL.
- **Operational consequences**: (a) moderate complexity; (c) minimal
  ops but weak incident response.
- **Recommendation**: (a) — matches lease-revocation's existing shape
  (RevokedAt already in the model), adds freshness via epoch.
- **Rationale**: the only option that supports "kill it now AND prove
  the view is fresh."
- **Status**: LEANS (a) — OPEN.

## D-06 Anchor model

- **Question**: how are receipt checkpoints externally anchored?
- **Options**: (a) append-only remote service (index-conflict = fork
  = alert); (b) Merkle transparency log (inclusion proofs); (c)
  signed checkpoints to immutable object storage.
- **Security consequences**: (a) detects post-anchor rewrite/fork —
  the stated claim; anchor honesty assumed. (b) strongest evidence,
  proves inclusion. (c) durability via storage policy, weaker
  freshness.
- **Operational consequences**: (a) thin HTTP service, near-zero
  work — `anchor_url` stub already exists. (b) real protocol
  complexity. (c) dependency on storage provider policy.
- **Recommendation**: (a) minimum viable, matching the existing stub;
  (b) is the honest upgrade when evidence requirements grow.
- **Rationale**: claim scoping — anchoring adds existence-at-T, not
  completeness or execution; (a) delivers exactly that.
- **Status**: LEANS (a) — OPEN.

## D-07 Monitor placement

- **Question**: where does the integrity monitor's trust anchor live?
- **Options**: (a) external watchdog process (separate uid/caps,
  out-of-band reporting); (b) TPM-measured state + external verifier;
  (c) remote attestation service with dead-man timer.
- **Security consequences**: (a) trust = process+uid separation +
  report path — defeatable by host-level compromise but NOT by
  agent-level. (b) strongest; hardware dependency. (c) good liveness
  story, still needs a local reporter to attest.
- **Operational consequences**: (a) deployable anywhere; (b) needs
  TPM; (c) needs an external service.
- **Recommendation**: (a) as the floor — agent can't write/ptrace it
  (capability separation is already the RC1 assumption class), and it
  reports on a path the agent can't reach. Layer (c) for liveness.
- **Rationale**: I8 is meaningless if it shares Ovara's trust; a
  separate process is the cheapest real separation.
- **Status**: LEANS (a)+(c) — OPEN.

## D-08 Gateway identity: ID vs keypair

- **Question**: should gateway identity (`gw_<id>`) be backed by a
  keypair so audience binding authenticates, not just names?
- **Options**: (a) keep ID-only (RC1); (b) gateway keypair signs
  receipts/checkpoints + audience verifies key-bound identity.
- **Security consequences**: (a) enrollment.json clone = cloned
  audience (T-ENROLL-CLONE). (b) clone needs the private key —
  real binding; new key-management burden.
- **Operational consequences**: (b) adds key provisioning/rotation to
  enrollment.
- **Recommendation**: (b) — required to make audience binding a
  *cryptographic* property rather than a name match; without it
  I6 is configuration-scoped.
- **Rationale**: REQUIRED-BY-INVARIANT candidate — the only option
  that closes T-ENROLL-CLONE.
- **Status**: LEANS (b) — OPEN (flagged as likely required for I6).

## D-09 Registry + issuer co-location

- **Question**: can the identity registry and credential issuer be
  one service?
- **Options**: (a) same service (one root); (b) separated.
- **Security consequences**: (a) single compromise mints identities
  AND credentials — unrevocable-ish root. (b) two-party compromise
  needed.
- **Operational consequences**: (a) much simpler.
- **Recommendation**: (b) for the security model; accept (a) only in
  single-operator deployments with the blast radius documented.
- **Rationale**: separation of mint-identity vs mint-credential is
  the core P2 trust partition.
- **Status**: OPEN.

## D-10 Staleness budget values

- **Question**: concrete staleness budgets for revocation view and
  credential-validity cache?
- **Options**: seconds / 30–120s / minutes-hours.
- **Security consequences**: tighter = closer to real-time revocation,
  more outage-denials.
- **Operational consequences**: tighter = more load + stricter clocks.
- **Recommendation**: credential validity ~60s, revocation ~30s
  default, operator-tunable within a declared max.
- **Rationale**: matches "not wire-speed revocation" non-goal while
  keeping incident response meaningful.
- **Status**: LEANS — OPEN.

---

## Deferred / out-of-scope decisions

- Multi-tenant trust domain partitioning (out of P2 scope)
- Running-execution retroactive kill on revocation (documented
  non-goal)
- Transparency-log-grade evidence (escalation path in D-06(b))

# OVARA 2.0 — P2 Threat Model (Trust & Lifecycle)

Status: DESIGN ONLY. Nothing here is implemented. RC1 is the frozen
baseline (`docs/OVARA_RC1_FREEZE.md`); P2 must not weaken any RC1
security invariant.

## 1. Scope

P2 addresses the properties RC1 deliberately deferred: credential
lifecycle, persistent identity, durable replay protection, runtime
delegation revocation, receipt anchoring, final network containment
verification, and integrity monitoring (I8).

Central question: **how does Ovara remain secure when credentials,
state, processes, machines, gateways, keys, and evidence change over
time or are partially compromised?**

RC1 established the enforcement boundary — a single correct decision
at a single point in time. P2 must build the trust + state + lifecycle
boundary around it: what stays true *across* time, restarts, replicas,
and partial compromise.

## 2. RC1 baseline (inventory)

Every row below is what exists today — not what is planned.

| Component | Current implementation | Trusted by | Persistence | Lifetime | Revocation | Failure mode | Security consequence |
|---|---|---|---|---|---|---|---|
| Agent credential | Static bearer token in `agent_tokens` config | Gateway auth middleware | Config file | Until config edit + restart | None (config replacement) | Invalid token → 401 | Whole principal = token hash; theft = full identity theft until restart |
| Operator credential | Static bearer token in `operator_tokens` | Same | Config file | Same | Same | Same | Full admin incl. approve/resume/unrestrict/policy write |
| Principal | `ag_/op_<sha256(token)[:16]>` | Everything downstream | Derived, none | = token lifetime | = credential | Identity dies with token | Identity is NOT independent of credential (P2 changes this) |
| Gateway identity | `enrollment.json` — self-generated `gw_<id>` | Audience checks | File | Until file deleted | None | Regenerated on fresh state | Audience binds to a *name*, not a key — a cloned enrollment file is a cloned identity |
| Trusted issuers | `trusted_issuers` config map issuer→ed25519 pubkey | Delegation + lease verification | Config file | Until config edit | None (config removal) | Missing → delegation/lease validation fails closed | THE delegation trust root; compromise = minting power under that issuer ID |
| Delegation chain | ed25519-signed hops, canonical LP encoding | Evaluator | In request (none) | Per-hop expiry | None | Invalid → deny | Capability; narrows never elevates |
| Delegation nonce | Terminal hop's signed nonce | Replay check | In-memory map, 5-min TTL | 5 min / process | n/a | Restart → replayable | ARCHITECTURAL LIMITATION (B5) |
| Request nonce | Client-supplied | Replay check | In-memory map, 5-min TTL | 5 min / process | n/a | Same | Same class |
| Capability lease | ed25519-signed, issuer-verified, exact audience | Evaluator | In request + tracked in capabilities store | `expiry` | **Exists**: `RevokedAt` in file-backed capabilities store (`/v1/capabilities/revoke*`) | Unknown issuer → fail closed | Only artifact with any revocation today |
| Policy | Versioned rules file | Evaluator | File | Until rewrite | Version field only | Load error → fail closed (startup) | Agent-immutable (I6) |
| Approval | Server-recorded decision binding | Continuation | File or memory | Pending→resolved | Deny is terminal | Tampered fields → 404/400 | Single-use resume |
| Continuation | Bound to decision+approval | Orchestrator | File or memory | Until executed/expired | Deny kills | State machine enforces order | Executes only approved+queued |
| Decision | Evaluator output, decision_id | Approval binding | Decision cache (in-mem) | Cache TTL | n/a | Cache miss → re-evaluate | Every request fully evaluates |
| Proxy client auth | `Proxy-Authorization` bearer | Proxy | Config | Static | None | Wrong → 407 | The *proxy* authenticates to gateway with an agent credential |
| Credential injection | `credentials` config host→headers | Proxy upstream | Config + `${ENV}` | Process | None | http scheme → not injected | Highest-value secret class |
| Execution | Host executors (opt-in `enable_host_executors`) or sandbox | Orchestrator | Execution records file/mem | Per-execution | Kill via deny before queue | Disabled → never executes | Host execution is explicitly opt-in |
| Proxy receipts | ed25519 hash chain, `receipts.jsonl` | `-verify` | File | Append | n/a | Record failure → CRITICAL + fail-closed | Tamper-evident locally |
| Gateway receipts | HMAC-SHA256 (`receipt_signing_key`) | Store | File or memory | Retention-bound | n/a | Random key if unset → unverifiable after restart | Operator must set key for durable verification |
| Anchor stubs | `var/anchors.jsonl` chain heads; `anchor_url` option exists | Nobody yet | File | Append | n/a | Remote anchor never verified | Stubs only — no external anchor today |
| Trust/shield state | Per-principal violation counters | Evaluator | In-memory | Process | `unrestrict` (operator) | Restrict → escalate | Containment is real but ephemeral |
| Federation | `FederatedTrustClient` interface | Nobody | — | — | — | Never wired | Dead hook in default deployment |
| Control plane | `enrollment/cloud_client.go` HTTPS client | Enrollment sync | n/a | n/a | n/a | Unreachable → local mode | Optional; HTTPS-enforced |
| SDK | Python canon.py + client | Users | n/a | n/a | n/a | Dep-free canon verified | Byte-identical vectors |

## 3. Assets

Beyond RC1's list, P2 adds assets whose compromise is newly
meaningful:

- **Stable identity registry** (proposed) — whoever controls it
  controls "who is who"
- **Revocation state** (proposed) — whoever controls it controls what
  still works; rolling it back resurrects dead capabilities
- **Anchor checkpoints** (proposed) — whoever controls the anchor can
  fork history
- **Monitor trust anchor** (proposed) — whoever it reports to defines
  what "integrity" means
- **Issuer private keys** — still external, still single point of
  minting power per issuer ID
- **Existing durable state** — receipts, approvals, continuations,
  capabilities stores: rollback targets under restoration/backup
  attacks

## 4. Actors

| Actor | Trust level | P2-relevant power |
|---|---|---|
| Agent (potentially malicious) | None | Presents credentials, chains, leases, requests |
| Agent operator/dev | Semi | Chooses audiences, asks issuers for chains |
| Delegation issuer | High within own issuer ID | Mints capabilities; compromise = bounded blast radius |
| Lease issuer | High within own issuer ID | Same |
| Human approver | High | Resolves escalations; operator-scoped |
| Gateway operator | Highest in domain | Config: tokens, issuers, policy, executors |
| Control plane (optional) | High if enrolled | Enrollment, sync; remote compromise = supply-chain class |
| Storage layer | Medium | Hosts durable state; rollback-capable adversary |
| Anchor service (proposed) | TBD — must be *lower* trust than gateway | Sees checkpoints; must not be able to forge them |
| Integrity monitor (proposed) | Must be *outside* Ovara's trust | Watches Ovara; if it shares Ovara's trust it is useless |

## 5. Trust boundaries

RC1 boundaries hold. P2 adds:

```text
TRUSTED                              UNTRUSTED / ADVERSARIAL
──────────────────────────────────────────────────────────
identity registry (proposed)          caller-supplied identity docs
revocation store (proposed)           stale revocation snapshots
anchor checkpoints (proposed)         local receipt files pre-anchor
monitor measurements (proposed)       Ovara's own self-reports
replicated state (multi-gateway)      unsynced replicas, split brain
backup/restore media                  restored-but-revoked state
```

**The core P2 boundary**: *current* authoritative state vs *stale or
replayed* state. Every P2 mechanism is a state-synchronization problem
between a trusted writer and possibly-stale readers.

## 6. Trust roots (P2)

RC1 roots: `trusted_issuers` config, operator/agent tokens, receipt
signing keys, proxy CA. P2 proposes additional roots — each needs an
owner, rotation, revocation, blast-radius answer:

| Proposed root | Creates | Private material | Rotate | Revoke | Compromise blast radius |
|---|---|---|---|---|---|
| Identity registry | Stable agent IDs | Registry signing key | Registry operator | Registry admin | Mint/rebind any identity in the domain |
| Credential issuer | Bearer creds | Issuance key / HSM | Same | Registry | Mint credentials for any identity |
| Revocation authority | Revocation statements | Revocation signing key | Operator | Governance | Forge or suppress revocations globally |
| Anchor service | Checkpoint attestations | Anchor signing key | Service operator | Governance | Fork/rewrite accepted history |
| Monitor trust anchor | Integrity verdicts | Monitor report key | Host admin | Host admin | Declare compromised systems healthy |
| Multi-gateway consensus | Shared replay/revocation state | Cluster member creds | Cluster operator | Quorum | Per-cluster scope |

For every root the same 11 questions apply (from the P2 brief):
who creates, where private material lives, who rotates, who revokes,
compromise consequence, blast radius, restart-survival, cross-tenant
reach, identity-minting, capability-minting, evidence-rewriting.

**Trust graph (derived, not assumed):**

```text
ROOT: operator-controlled config + external issuer keys + registry keys
  │
  ├─ trusted_issuers ──► issuer signatures ──► delegation chains ──► capability
  │                      issuer signatures ──► leases ──► capability
  │
  ├─ credential issuer (P2) ──► bearer credentials ──► authenticated principal
  │        ▲                                              │
  │        └──── identity registry (P2) binds ◄───────────┘
  │
  ├─ revocation authority (P2) ──► revokes: issuers / identities /
  │                                credentials / chains / leases
  │
  ├─ gateway (evaluator) ──► decisions ──► approvals ──► executions
  │        │
  │        └─► receipts ──► local hash chain ──► anchor checkpoints (P2)
  │                                             ──► external anchor (P2)
  │
  └─ integrity monitor (P2, external to Ovara) ──► watches ALL of the above
```

## 7. Security assumptions (P2 additions)

| # | Assumption | If violated | Detectable? |
|---|-----------|-------------|-------------|
| C1 | Identity registry writes are authenticated + ordered | forged/misbound identities | audit log + signatures |
| C2 | Revocation store reads are fresh enough for the decision | stale allow for revoked capability | staleness bound config |
| C3 | Durable store is not adversarially rolled back | consumed nonces resurrect | anchor checkpoints |
| C4 | At most one gateway authority per trust domain unless clustered | cross-domain replay | domain scoping |
| C5 | Monitor's reporting path is independent of Ovara's runtime | silent compromise | dead-man / external verifier |
| C6 | Anchor endpoint authentication is sound | forged checkpoints | signature verification |
| C7 | Clock skew bounded (for TTLs/expiry) | premature expiry / extended validity | NTP assumption |
| C8 | Backup restoration is operator-visible | silent resurrection | restore hooks + events |

## 8. Attack surfaces (P2 additions)

| Surface | Class | Notes |
|---|---|---|
| Identity registry API | New | Mint/rebind/steal identities |
| Credential issuance API | New | Mint credentials |
| Revocation API/store | New | Suppress or forge revocations |
| Replay state store | New | Rollback to resurrect nonces |
| Anchor submission endpoint | New | Forge/omit checkpoints |
| Monitor reports | New | Declare compromised = healthy |
| Replication between gateways | New | Split-brain double-spend of a capability |
| Backup/restore path | Existing, newly material | Restores revoked state |
| Multi-gateway shared caches | New | Trust-domain confusion |

## 9. Threats (P2-specific)

1. **T-REPLAY-RESTART**: valid chain re-presented after restart —
   RC1-documented, P2 must kill or bound it.
2. **T-ROLLBACK**: backup restore resurrects revoked
   credentials/chains/consumed nonces.
3. **T-SPLIT-BRAIN**: two gateway replicas each accept a capability
   once — same capability executes twice.
4. **T-STALE-CRED**: rotated-out credential still authenticates.
5. **T-IDENTITY-SUB**: attacker binds their credential to a victim's
   stable identity.
6. **T-ISSUER-COMP**: compromised issuer mints chains (RC1 blast-radius
   analysis holds) — P2 adds revocation path.
7. **T-REVOCATION-SUPPRESS**: attacker blocks revocation propagation so
   a dead capability keeps working.
8. **T-EVIDENCE-FORK**: two divergent receipt histories both anchor;
   which is canonical?
9. **T-MONITOR-BLIND**: attacker compromises the monitor or its
   report path — the watcher problem.
10. **T-ENROLL-CLONE**: gateway identity file copied to attacker
    machine → audience-bound credentials validate at the clone.
11. **T-PARTITION-REVOCATION**: gateway partitioned from revocation
    source — must it fail closed (deny) or accept staleness?
12. **T-REGISTRY-TAKEOVER**: whoever writes the identity registry
    becomes the real root of trust.

## 10. Attack trees

```
GOAL: execute an unauthorized action
├── 1. Forge credentials            → blocked by signature/registry (P2-C)
├── 2. Steal valid credential       → mitigated by rotation+revocation (P2-C)
│   └── 2a. use stale rotated cred  → killed by generation checks (P2-C)
├── 3. Replay valid capability      → killed by durable replay (P2-D)
│   ├── 3a. after restart           → durable store (P2-D)
│   └── 3b. at second gateway       → shared/authority-scoped store (P2-D)
├── 4. Revoked-but-still-working    → revocation propagation (P2-R)
│   ├── 4a. exploit stale snapshot  → staleness bound / fail closed (P2-R)
│   └── 4b. suppress revocation     → signed statements + freshness (P2-R)
├── 5. Erase evidence               → anchoring + monitor (P2-A/I8)
│   ├── 5a. delete local receipts   → anchor divergence detected
│   ├── 5b. rewrite history         → hash chain + anchor head mismatch
│   └── 5c. kill the monitor        → dead-man alert (I8)
└── 6. Modify Ovara itself          → integrity monitor external to
    the modified runtime (I8) — else unwinnable
```

## 11. Security invariants (P2)

See §11 of the design doc for the full I1–I20 matrix with property /
threat / assumption / enforcement / verification / failure mode.

The load-bearing P2 invariants:

- **I2 identity-stability**: a principal survives credential rotation
  without changing identity.
- **I3 revocation**: a revoked artifact (credential, issuer, chain,
  lease, identity) cannot authorize new actions after propagation.
- **I11 durable replay**: within the capability lifetime, one
  presentation → at most one accepted evaluation, across restarts and
  (where deployed) replicas.
- **I14 anchoring**: receipt history accepted before anchoring cannot
  be silently rewritten after anchoring.
- **I16 boundary integrity**: modification of the enforcement boundary
  is detectable by a party that does not trust Ovara.
- **I20 propagation**: revocation reaches enforcement points within a
  defined bound or they fail closed.

## 12. Failure modes (what "safe" means when things break)

| Failure | P2-required behavior |
|---|---|
| Identity registry down | Auth continues on existing creds OR fails closed — DECISION (availability vs strictness) |
| Revocation store unreachable | Bounded staleness → escalate, not silent allow — DECISION |
| Replay store down | Deny (cannot prove non-replay) — recommended |
| Anchor unreachable | Local receipts continue; flag unanchored state — never block transit on anchoring |
| Monitor detects tamper | Contain + alert; what it cannot do is un-detect |
| Backup restored | Post-restore reconciliation vs revocation/replay/anchor state |
| Registry compromise detected | Re-bind identities under governance; all registry-signed artifacts suspect |

## 13. P2 requirements (derived from threats)

1. Identity and credential must be separable: credential rotates,
   identity persists.
2. Revocation must cover: credentials, issuers, delegation chains,
   leases, identities — with bounded propagation and defined
   staleness behavior.
3. Replay protection must survive restart and have a defined
   multi-instance story or a declared single-authority boundary.
4. Anchoring must make post-anchor history rewrite detectable by an
   external verifier, without blocking the data plane.
5. The integrity monitor must trust something Ovara does not control.
6. Every new trust root gets an explicit owner/rotation/revocation/
   blast-radius entry — no silent new roots.
7. Fail-closed default on every state-dependency failure, with
   explicit operator-visible degradation modes.
8. RC1 invariants hold throughout: identity binding, capability
   narrowing, policy independence, approval binding, custody,
   execution gating, receipt integrity.

## 14. Deferred risks (accepted even after P2)

- Host kernel compromise (A7 stands)
- Insider with legitimate operator credentials and governance access
- Side-channel exfiltration inside allowed traffic
- Multi-agent collusion via allowed third-party services
- Availability of upstreams/anchors (not a confidentiality boundary)

## 15. Open questions (feed the decision record)

- Single-writer vs replicated replay state — what is the deployment
  model actually being secured?
- Is revocation pull (cached, staleness-bound) or push (propagated)?
- Does the anchor prove *existence-at-time-T* or *ordering*, and is
  that enough to detect rollback?
- Who operates the monitor trust anchor when Ovara is deployed by one
  team on one host?
- Can identity registry and credential issuer be the same service
  without creating an unrevocable root?
- What is the staleness budget for revocation — seconds, minutes?

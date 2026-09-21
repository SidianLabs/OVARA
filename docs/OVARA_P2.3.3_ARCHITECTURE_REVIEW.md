# OVARA 2.0 — P2.3.3 Architecture Review
## Oracle-based anti-rollback: does the proposed boundary actually hold?

Status: REVIEW of `OVARA_P2.3.3_ROLLBACK_ANCHORING_DESIGN.md`.
Design only — nothing implemented, nothing committed by this document.

## Executive Summary

The proposed mechanism — a signed monotonic checkpoint oracle plus a
hash-chained local journal — **passes the independence test** and
genuinely kills the two demonstrated rollback attacks, PROVIDED the
oracle's compare-and-store state lives in a store the registry attacker
cannot replace. The mechanism is sound; the design needs six precision
amendments, not a redesign:

1. The threat model must distinguish *registry-file* attacker from
   *whole-directory* attacker — `gateway_key`, `gwreg.jsonl`, and
   `enrollment.json` all live in `var/data/`. The design's own diagram
   places the signing key inside the attacker boundary while R7 assumes
   "fs write ≠ key possession." Resolution (§5): monotonicity is
   enforced by the oracle's max-store, not by the signature — rollback
   resistance survives even key compromise; what key theft actually
   buys the attacker is forward-hijack and bootstrap-race, which must
   be named.
2. The failure matrix lacks oracle-backup-restore and joint co-rollback
   rows (§8).
3. The gateway side has no specified oracle-identity verification —
   a config-pinned oracle identity is required (§10).
4. Checkpoint fields must be trimmed to the security-critical set (§5).
5. Migration is an attestation event, not a forensic one — it cannot
   detect a rollback that happened before migration (§15).
6. The oracle's own store needs an independent durability story —
   "who anchors the anchor" is answered "nobody; that's the trust root,"
   which must be stated as a requirement, not left implicit (§11/§18).

Verdict: **PASS, conditional on the six amendments being folded into
the design before implementation.**

## Current P2.3.2 limitation

The journal is self-authenticating only for integrity, never for
*latestness*. Everything inside the file rolls back with the file:
consumed grants replay, retired gateways resurrect, truncated prefixes
become authoritative. P2.3.2.1 verified this is an ARCHITECTURAL
LIMITATION — there is no external reference for "newest seen." That is
the entire gap P2.3.3 must close; it must not claim more.

## Threat Model

The design's capability list (A–J) is correct; the granularity is not.
Two attacker scopes must be separated:

| Scope | Holds | P2.3.3 outcome |
|---|---|---|
| **Registry-file attacker** | r/w/replace `gwreg.jsonl` only | Fully defeated — cannot roll back (R1–R4), cannot forge checkpoints (no key) |
| **Directory attacker** | r/w all of `var/data/` incl. `gateway_key` | Cannot roll back (oracle max-store still monotonic — signature is authentication, not the monotonic element); CAN forward-hijack (push seq=N+k forged tip → honest pushes rejected = availability kill) and contest bootstrap |
| **Host attacker (root)** | everything on the host incl. local-oracle store | Only a REMOTE oracle survives; a co-located oracle's store is equally replaceable |
| **Anchor compromise** | oracle's store/key | Out of scope — not claimed |
| **Operator compromise** | reset credential | Out of scope — operator is the trust root |

The important property this exposes: **rollback protection is enforced
by the oracle's compare-and-store semantics, not by cryptography.**
Signatures authenticate writers; they do not create monotonicity. Even
a gateway-process compromise (holds the key, pushes signed checkpoints)
cannot decrement the oracle — R1–R4 survive it. That is a stronger
claim than the design made, and it is the right one.

## Trust Boundaries

```
registry file ──(replaceable)──► journal fold ──► authority decision
       │                                 ▲
       └─── signed checkpoint push ──────┤
                                        │  compare-and-store max(seq)
                                   ┌────┴─────┐
                                   │  ORACLE  │  ← the ONLY state the
                                   │  store   │    attacker must not reach
                                   └──────────┘
```

Independence test, answered exactly: *if the attacker has complete
read/write control over the registry file and can restart the gateway,
can they also restore or replace the oracle state?*

- Remote oracle: **NO** — different host, different store, different
  credential. The boundary is real.
- Co-located oracle process (separate uid + separate dir): **NO** for
  the registry-file and directory attacker — **YES** for the root/host
  attacker. Real boundary, narrower claim.
- Oracle state inside the same directory/file: **YES — FAIL** (this is
  Option A rejected by the design, correctly).

## Oracle Placement Comparison

| Axis | A. Local oracle process | B. Extend existing service | C. Remote control-plane | D. External append-only infra | E. Hybrid (recommended) |
|---|---|---|---|---|---|
| Trust boundary | uid + dir separation | same-host or remote, deployment-dependent | network + host + credential | third-party ledger | C-protocol, deployable as A or C |
| Defeats host/root attacker | NO | only if remote | YES | YES | only in remote tier |
| Process/fs isolation | real but same kernel | varies | full | full | per tier |
| Credential isolation | separate uid secrets | varies | separate PKI/channel | third-party auth | per tier |
| Compromise impact | oracle store replaceable by root | same | oracle = new trust root | ledger compromise | anchor compromise (out of scope) |
| Bootstrap | trivial | moderate | needs channel auth + TOFU | heaviest | TOFU + operator confirm |
| Availability | no network dep | varies | partition = mutation/boot downtime | partition + vendor dep | same as C in remote tier |
| Offline behavior | works | varies | strict-refuse | strict-refuse | configurable |
| Operator recovery | simple | moderate | reset ceremony | vendor procedures | reset ceremony |
| Deployment complexity | one more daemon | reuse | new service or endpoint | new external dep | smallest that crosses a real line |
| Upgrade/migration | local | varies | fleet coordination | vendor | fleet coordination |
| Failure behavior | local refuse | varies | fail-closed | fail-closed | fail-closed |

Facts, not rankings: A is the cheapest boundary that crosses *any*
line; C is the only one that defeats a full local attacker; D still
needs an oracle-semantics layer on top (a ledger proves existence, not
latestness — same critique as the receipt option); E = the C protocol
with deployment-tiered placement and per-tier claims.

## Recommended Trust Boundary

**The boundary is the oracle's compare-and-store state, placed outside
the attacker's reach.** Concretely: a minimal oracle service exposing
`PUT /v1/anchor/{domain}` (verify signature; accept seq > stored, or
seq == stored with identical tip_hash as idempotent retry; reject all
else) and `GET /v1/anchor/{domain}` (return stored checkpoint).

Two deployment tiers, one protocol, claims labeled per tier:

- **Tier 1 — co-located daemon** (separate uid, separate 0700 dir,
  separate store): protects against registry-file attacker, directory
  attacker, local process attacker, and operational accidents. Does
  NOT protect against root/host attacker. This tier matches the
  current single-host embedded threat model.
- **Tier 2 — remote oracle**: additionally defeats full local attacker
  including root. Required for any multi-host/fleet claim anyway.

TPM remains an orthogonal third anchor where hardware exists — it is
the only tier-1 mechanism that survives root.

## Checkpoint Model

Security-critical fields (the oracle compares/stores on exactly these):

- `domain_id` — the authority domain (genesis-derived)
- `seq` — journal sequence (the monotonic value; NOT a separate
  checkpoint counter — `checkpoint_seq` is redundant for monotonicity,
  retained only as oracle-side dedup metadata)
- `tip_hash` — chain hash binding the entire journal prefix
- `key_id` — signer identification for lineage checks
- `sig` — Ed25519 over the canonical serialization of the above

Informational only: `timestamp` (never ordered on), `gw_id` (audit),
checkpoint_seq (dedup metadata). Remove from the model: previous-
checkpoint reference (the journal chain already binds history — a
second chain is redundant), any "authority state" field (derivable from
the verified journal — never anchor derivable state).

Amendment: the oracle must NOT require seq contiguity. Pushes carry
tips; a crash spanning several commits then a boot re-push legitimately
skips seqs. Requiring contiguity would turn crash recovery into a
false conflict.

## Monotonicity Model

"Monotonic" means: the oracle's accepted sequence per domain is totally
ordered and strictly grows; `seq` may only advance, never regress, for
the lifetime of the domain.

| Event | Oracle behavior |
|---|---|
| duplicate checkpoint (identical seq+hash) | idempotent accept — makes push retry-safe |
| replayed checkpoint (seq < stored) | reject |
| skipped checkpoint (gap in seq) | accept — tips only, contiguity not required |
| out-of-order | reject (seq ≤ stored) |
| restored checkpoint | reject (seq < stored) |
| conflicting checkpoint (same seq, different hash) | reject + ALERT — split-brain or attack signal |
| oracle restart | stored max must be durable before ack (fsync/replicated) — else a restart silently lowers the ceiling |
| gateway restart | boot reconcile (§8) |
| gateway rollback | seq < stored → refuse |
| oracle rollback | gateway's intact journal self-heals via re-push — see §8 |

Oracle-side state: exactly `(domain_id → seq, tip_hash, accepted key
lineage)`. Nothing else is needed; anything more is attack surface.

## Bootstrap

First checkpoint establishes domain ⇄ key lineage at the oracle:

1. Genesis: first authority transition emits checkpoint #1; oracle
   accepts it only for an unregistered domain_id over the gateway's
   PoP-authenticated channel.
2. Operator confirmation (REQUIRED, not optional): the operator
   compares `gwctl anchor-status` output — registered `{domain_id,
   genesis tip_hash, active key fingerprint}` — against the local
   `{enrollment id, key fingerprint, journal tip}` shown by `gwctl`.
   The artifact compared is the (domain_id, pubkey fingerprint) pair.
3. Attacker-as-first-authority: first-write-wins per domain. If an
   attacker registers the domain first, the real gateway's registration
   conflicts → refusal + alert. Skipped operator confirmation degrades
   the property from VERIFIED to detectable-failure, not to silent
   compromise — say so.
4. Key rotation: rotation checkpoint dual-signed by retiring + new key
   during the existing grace window; oracle advances accepted lineage.
   Oracle-side key lineage follows the same rule — an oracle key
   rotation is itself a signed operator event.
5. Backup restore / P2.3.2 migration: §15 — operator attestation.

## Recovery Matrix (complete — every row decided)

Notation: `L` = local journal tip, `A` = oracle-stored, `W` = last-seen
anchor watermark recorded in the journal (observability aid, §11).

| Case | Decision |
|---|---|
| L == A | ALLOW |
| L.seq > A.seq, chain valid | RECOVER — re-push current tip (contiguity not required); if W == A: clean crash-recovery; if W > A: oracle regressed → ALERT |
| L.seq < A.seq | DENY — rollback detected; operator reset ceremony or re-provision |
| L.seq == A.seq, hash ≠ | DENY + ALERT — corruption/forgery |
| Oracle unavailable at mutation | DENY the mutation (strict); journal unchanged |
| Oracle unavailable at boot | DENY trust-init (strict). No safe local shortcut exists — §9 |
| Oracle unavailable while running | ALLOW — reads never consult oracle |
| Oracle corrupted/unparseable | DENY + ALERT — oracle-side recovery |
| Oracle returns conflicting checkpoint (same seq, diff hash) | DENY + ALERT — split-brain signal |
| Oracle returns OLDER checkpoint | covered by L>A row — RECOVER via re-push (+ ALERT if W > A: oracle regressed) |
| Oracle returns NEWER than any local history | DENY — local journal is older than authoritative history (same as rollback row) |
| Gateway restored from backup | L.seq < A → DENY; intentional → operator reset ceremony |
| **Oracle restored from backup** | its stored seq lower → RECOVER via gateway re-push; alert if the gap is anomalous. Requires oracle store durability independent of gateway backups |
| **Joint restore (registry + oracle to consistent old state)** | UNDETECTABLE — this IS the anchor-compromise boundary. Named residual; mitigated only by independent durability schedules |
| Gateway retired | tombstone is in anchored history — survives any registry restore |
| Consumed grant after rollback | same — R2 |
| Key rotation after rollback attempt | rolled-back journal has seq < A → DENY; rotation lineage on oracle only advances (dual-sign) |
| First boot without oracle connectivity | strict: DENY (cannot distinguish "new domain" from "rolled-back domain" without the oracle) |

## Failure Semantics (fail-closed scope)

What strict mode blocks on oracle failure:

- Startup/trust-init: **YES** — running on possibly-stale history is
  the attack. No local watermark can soften this: any "registry
  unchanged since last sync" proof stored on the same filesystem is
  forgeable by the directory attacker. Strict-refuse is the correct
  floor; a softer "serve-if-unchanged" mode is possible ONLY for tier-1
  scoped-attacker deployments and must be labeled as such.
- Admission (new bindings): **YES** — mutation.
- Grant/deny/retire/rotate/revoke: **YES** — mutations.
- Already-authorized runtime operation (PoP auth, action evaluation,
  adopt-existing-binding while running): **NO** — read-only paths never
  touch the oracle. A partition does not take down a running gateway;
  it freezes authority *changes*. That is the correct scoping:
  security-critical transitions fail closed, ordinary operation keeps
  serving.

## Cryptographic Trust Model

- Signing key: gateway's active Ed25519 key; lineage advanced by
  dual-signed rotation checkpoints. The key's home is `var/data/` —
  protected only by 0600. **State the bound honestly**: R7 holds
  against the registry-file attacker; against the directory attacker
  the signature authenticates nothing the attacker can't also sign —
  but rollback still fails because monotonicity lives in the oracle's
  store, not the key. For directory-attacker deployments, consider an
  anchor-dedicated key outside the shared dir — listed as an option,
  not required for the core claim.
- Oracle identity: **AMENDMENT — required.** The gateway must pin the
  oracle's identity (config-pinned cert/pubkey, same pattern as
  `trusted_issuers`). Without it a MITM can impersonate the oracle;
  impact is bounded (fake-new A → refuse = availability; A_old →
  self-heal) but the pin is cheap and clarifies failure semantics.
- Trust root: operator — confirms domain registration, holds reset
  credential, pins oracle identity.
- Circularity check: gateway trusts oracle's stored max; oracle trusts
  gateway's key lineage — established at genesis when NO history exists
  to roll back, and operator-confirmed out-of-band. The dangerous
  circularity (oracle trusting the *current registry* to decide what's
  authoritative) does NOT exist: the oracle never reads the registry;
  it compares signed seqs. PASS — with the operator-confirmation
  step mandatory.

## TPM Analysis

TPM contributes exactly one thing: an increment-only NV counter —
monotonicity enforced in hardware. It is the ONLY placement that
survives a root attacker on a single host. What it does not provide:
availability independence (same host), network-free multi-gateway
consensus, or any improvement over the oracle for the scoped threat
model. Keep it optional: without it, the oracle provides all
R-invariants; with it, tier-1 deployments gain host-attacker
resistance the oracle alone can't give locally. Correct to keep it
non-baseline — TPM absence on the embedded fleet is real.

## Receipt Analysis

Observability/audit-only — confirmed, not security-critical. A receipt
proves a checkpoint was emitted; it cannot answer "what is newest."
Publishing checkpoint events to the receipt service gives operators a
tamper-evident trail for detecting oracle-side tampering *after the
fact* — a genuine detection aid, zero authority role. No circularity:
receipts consume checkpoint output; they never gate authority. The
design is correct here; do not let future work creep receipts into the
decision path.

## Attack Analysis

| # | Attack | Outcome |
|---|---|---|
| A | restore pre-consumption | PREVENTED — L.seq < A → refuse |
| B | restore pre-retirement | PREVENTED — same |
| C | older valid snapshot | PREVENTED — same |
| D | modified snapshot | PREVENTED — chain-hash mismatch or seq < A |
| E | replace + restart | PREVENTED — boot reconcile refuses |
| F | replay old checkpoint | PREVENTED — seq ≤ stored reject |
| G | replay old signed checkpoint post-newer | PREVENTED — same (signature doesn't rescue staleness) |
| H | forge newer checkpoint | needs domain key — registry-file attacker: PREVENTED; directory attacker: forward-hijack (availability kill, NOT rollback) — named residual |
| I | compromise gateway process | cannot decrement oracle → R1–R4 hold; forward forgery = conceded fs-authority |
| J | compromise oracle | OUT OF SCOPE — mitigations: signed trail exposes tampering, conflicting-checkpoint alerts |
| K | oracle unavailable | mutations/boot fail closed (strict); running ops unaffected; degraded-mode window documented |
| L | bootstrap race | first-write-wins + PoP channel + operator confirm; skipped confirm = detectable failure |
| M | domain substitution | domain_id signed + oracle keying → foreign domain is just a different slot |
| N | gateway identity substitution | needs lineage key; cloned key+registry = documented clone residual — cannot move oracle backwards |
| O | key rotation rollback | rolled-back journal seq < A → refuse; lineage only advances |

## R1–R12 Invariants (as required by spec, mapped to design)

- **R1** authority history cannot move backwards — oracle max(seq). HOLDS.
- **R2** consumed grant cannot become pending — via R1. HOLDS.
- **R3** retired gateway cannot reactivate — via R1. HOLDS.
- **R4** restored registry cannot increase authority — restore is strictly older; fabricated-newer still cannot reclaim oracle-recorded terminal states. HOLDS.
- **R5** old checkpoint not accepted as newer — seq ≤ stored rejected. HOLDS.
- **R6** checkpoint bound to one domain — domain_id signed + keyed. HOLDS.
- **R7** attacker-controlled registry cannot forge newer checkpoint — holds for registry-file attacker; for directory attacker degrades to forward-hijack (availability), NEVER rollback. Scoped honestly.
- **R8** crash cannot produce two valid histories — fsync-then-push + per-(domain,seq) uniqueness. HOLDS.
- **R9** required oracle failure fails closed — strict mutation/boot refusals. HOLDS.
- **R10** bootstrap not attacker-controlled — TOFU + PoP + operator confirm. HOLDS under confirmed ceremony.
- **R11** gateway rollback cannot roll back oracle state — gateway has no regression channel (compare-and-store rejects). HOLDS by construction.
- **R12** oracle rollback cannot silently roll back authoritative state — gateway re-push restores the ceiling; joint co-rollback is the named residual (anchor compromise). HOLDS except joint-restore — stated.
- **R13** journal prefix integrity oracle-free — tip_hash chain; mid-file modify detected locally.
- **R14** no silent authority-mode change — degraded/override transitions journal-logged and loud.

## Migration Plan

1. `anchor_mode=off` ships first — zero behavior change.
2. `gwctl anchor-init`: assigns seq + chain hashes in file order,
   appends a `kind:"migrate"` marker (never rewrites lines), computes
   genesis tip.
3. **Operator attestation — the critical step**: the tool prints the
   full state summary (tip seq/hash, record counts, active keys,
   retired gateways, consumed grants). The operator verifies this IS
   the current authoritative state out-of-band, then confirms. The
   genesis checkpoint legitimizes whatever is present — **migration
   cannot detect a rollback that already happened**. It is an
   attestation event, not a forensic one. Documented limit.
4. Registration at oracle + `anchor_mode=strict`.
5. Pre-migration snapshot restored later → no seq/chain → invalid →
   refuse. Anchored snapshot → seq < oracle → refuse → reset ceremony.

## Deployment Model

- Tier 1 (embedded single-host): oracle as a separate-uid daemon,
  `anchor_mode=strict` still meaningful — defeats the scoped attacker
  class + all operational accidents. Claims limited to that scope.
- Tier 2 (remote): same protocol, oracle off-host. Required for
  full-local-attacker and fleet claims.
- `anchor_mode=off` = P2.3.2 behavior, documented weaker.
- `anchor_mode=degraded` = bounded rollback window during partition,
  opt-in, never default.

## Open Questions

1. Oracle placement: standalone service vs endpoint on an existing
   service — decide by deployment shape; the protocol is identical.
2. Oracle store durability: required independent of gateway backup
   schedules (joint-restore hole). Replication vs independent snapshot
   policy — ops decision, must be explicit.
3. Offline-only deployments with no network path and no TPM: accept a
   documented "no rollback resistance" tier or mandate hardware?
4. Reset-credential strength: same fs-authority as gwctl, or a
   distinct operator factor for anchor-reset?
5. Directory-attacker deployments: anchor-dedicated key outside
   `var/data/` — worth the extra file?
6. Multi-writer domains (future): writer-id dimension needed if two
   gateways ever share one domain.

## Implementation Preconditions

Before any P2.3.3 code:

1. Fold the six amendments into the design doc (key-boundary scoping,
   co-rollback residual, oracle-identity pin, checkpoint field trim,
   migration attestation, oracle durability requirement).
2. Land the deferred integration wiring commit — `server.go` /
   `config.go` carry entangled P2.2+P2.3.x diffs that were deliberately
   left out of 56640f8; they need their own freeze step.
3. Decide oracle placement for the target deployment tier.
4. Decide the reset-credential mechanism.
5. Write the P2.3.3 threat-model update distinguishing registry-file
   vs directory attacker before any claim is phrased.

---
*Review produced per P2.3.3 oracle-architecture-review task. No code,
no commits, no runtime changes.*

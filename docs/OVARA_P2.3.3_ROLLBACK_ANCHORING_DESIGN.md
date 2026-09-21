# OVARA 2.0 — P2.3.3 Rollback & Authority-History Anchoring
## Design Review Report (DESIGN ONLY — no implementation)

Status: amended per architecture review (PASS-conditional). The six
required amendments are folded in below as **normative requirements**
(marked AM-1..AM-6). Nothing here is implemented.

## 1. Problem statement

The P2.3.2 registry journal is authoritative only while its own history
is intact. The journal is a file; the attacker model grants filesystem
write as authority. Whoever can replace the file can restore an earlier
authoritative state, and nothing inside the file can refute it — any
integrity value stored *in* the journal rolls back with it.

The demonstrated attacks (P2.3.2 audit, P2.3.2.1 §10 row D):

- restore → pre-consumption snapshot: a `consumed` grant is usable again
- restore → pre-retirement snapshot: a `destroyed` gateway is ACTIVE again
- prefix-truncate + restart: earlier history becomes authoritative
- in-process aligned rewrite ≥ committed offset: injected records fold in
  undetected (accepted as a forward transition — equivalent to fs write,
  which already *is* authority; the dangerous class is history
  *shortening/replacement*)

The open question P2.3.3 must answer:

> How does Ovara know that the current authority history is not older
> than an already-observed authoritative history?

"Already-observed" must live in a place the attacker cannot replace
together with the registry. That place is the **anchor**.

## 2. Current P2.3.2 limitation (precise)

| Property | P2.3.2.1 state |
|---|---|
| Torn tail (crash mid-append) | Truncated on load — VERIFIED |
| In-process shrink < committed offset | Detected, fails closed — VERIFIED |
| In-process aligned rewrite | NOT detected — ARCHITECTURAL LIMITATION |
| Registry restore while stopped | NOT prevented — ARCHITECTURAL LIMITATION |
| Record modify mid-file | Corrupt → refuse — VERIFIED |
| Record reorder/duplicate | Last-wins fold — documented (F3) |

Everything the journal can prove about itself is already proven. The gap
is strictly: **no external reference point for "newest seen"**.

## 3. Threat model — AM-1 KEY-BOUNDARY SCOPING

### 3.1 Distinct principals (must never be conflated)

| Principal | What it is | Lives where |
|---|---|---|
| **Gateway private key** | signs PoP + checkpoints | `var/data/gateway_key` (0600) — same directory as the registry |
| **Oracle authentication key** | authenticates the gateway→oracle channel writer | gateway side (per deployment) |
| **Oracle verification identity** | the oracle's public identity the gateway pins | gateway config pin |
| **Domain trust root** | the oracle's compare-and-store state for the domain | oracle's own store — outside the gateway filesystem |
| **Operator/bootstrap authority** | confirms registration, holds reset credential | out-of-band — not any file in the trust domain |

### 3.2 Attacker scopes (the granularity the claims depend on)

| Scope | Holds | P2.3.3 outcome |
|---|---|---|
| Registry-file attacker | r/w/replace `gwreg.jsonl` only | Fully defeated: cannot roll back (R1–R4), cannot forge checkpoints (no key) |
| Directory attacker | r/w all of `var/data/` incl. `gateway_key` | Cannot roll back (oracle max-store still monotonic); CAN forward-hijack and contest bootstrap — §3.3 |
| Host attacker (root) | everything on the host | Only Tier-2 remote oracle survives — §12 |
| Gateway process compromise | runs the gateway code | Cannot decrement the oracle — R1–R4 survive; forward forgery = conceded fs-authority |
| Anchor compromise | oracle's authoritative store | **OUT OF SCOPE** — not claimed |
| Operator compromise | reset credential | **OUT OF SCOPE** — operator IS the trust root |

### 3.3 What key theft actually buys — normative statement

**Compromise of the gateway private key ≠ compromise of oracle monotonic
state.** Monotonicity is enforced by the oracle's compare-and-store,
not by the signature. With the key the attacker can:

- sign *newer* checkpoints → **forward-hijack**: push seq=N+k with a
  forged tip so the honest gateway's next push (seq < N+k) is rejected
  — an **availability kill**, not a rollback
- contest **bootstrap** (register the domain first — mitigated §7)
- mint forward authority — already conceded (fs write = authority)

The attacker **cannot** decrement the oracle's stored sequence without
compromising the oracle itself. Gateway-key theft is an
**availability/forward-authority risk, not an anti-rollback bypass.**
No claim is made against compromise of the oracle trust root.

### 3.4 Carried-forward capabilities (A–J)

A–F in scope (rewrite/replace/truncate/modify records, restart, kill
during admission). G read = not a threat. H fs write = conceded forward
authority. I anchor compromise = out of scope. J anchor unavailability
= in scope, availability design §12.

## 4. Security objective

> An attacker who can replace the local registry must NOT be able to
> restore previously consumed or retired authority without crossing an
> independent trust boundary.

Concretely: after any committed transition T (grant consumed, gateway
retired, key revoked/superseded), no registry state that omits T may be
accepted as authoritative again.

## 5. The core oracle model — three roles, no substitutes (PART B)

| Element | Its ONLY job | What it does NOT do |
|---|---|---|
| **Signature** | authenticates *who* produced the checkpoint | does not create monotonicity; does not prove the journal is newest |
| **Oracle monotonic state** | decides whether a checkpoint may move authority forward (compare-and-store max) | does not verify journal content; does not exist on the gateway filesystem |
| **Local hash chain** | detects modification/reordering of the local journal | does not know which valid chain is newest — a full-replacement alternative chain is equally "valid" internally |

**None of these alone provides rollback protection.** The security
property is their composition plus an **independent durability
boundary** (AM-6): the oracle's store must itself be durable or the
composition collapses to self-reference.

## 6. Candidate architectures

### Option A — Local monotonic OS-protected state

Linux offers no userspace monotonic primitive that survives an attacker
who can replace arbitrary files. Every candidate (a second file, xattrs,
a dedicated partition, systemd counters) is replaceable by the same fs
attacker — the "anchor" rolls back with the registry. It adds zero
independence.

- Secure against: operational accidents (backup restore, rsync mistakes)
  — a cheap `anchor.json` *outside* the registry path is worth having as
  a tripwire for exactly this, but it is NOT a security boundary.
- Not secure against: the P2.3.3 filesystem attacker.

Verdict: insufficient alone. May appear as the degraded-mode tripwire,
never as the claim.

### Option B — TPM-backed monotonic state

TPM 2.0 NV counter indexes increment only — a real monotonic primitive.
Design: on each authority transition, increment NV counter; journal
checkpoint carries `epoch = NV value`; on boot, journal epoch < NV value
→ fail closed. Sealed state alone does NOT solve rollback (the sealed
blob lives on the same replaceable disk) — the NV counter is the anchor,
sealing is just authenticated storage.

- Secure against: full filesystem attacker — cannot decrement NVRAM.
- Gaps: TPM absent on much of the embedded target fleet; NVRAM wear
  (~100k writes typical) argues for counter-per-boot-epoch not
  per-record; provisioning ceremony needed; an attacker who controls
  the TPM owner hierarchy is an anchor-compromise (out of scope anyway).
- Cost: new dependency (tpm2-tss or go-tpm), hardware requirement.

Verdict: genuinely strong where present — the only Tier-1 mechanism
that survives a root attacker. Not the baseline (fleet reality); an
optional hardware tier — §12.

### Option C — External control-plane checkpoint

A small oracle service stores the newest authoritative checkpoint per
domain: `(domain_id → {seq, tip_hash, key lineage})`. On every
authority transition the gateway pushes; on boot it fetches and
reconciles (§8).

- Latency: one RTT per authority mutation. Mutations are operator-rate
  (grant/deny/retire/rotate/admit), not request-rate — acceptable.
- Availability: mutations fail closed when oracle unreachable (§11).
  Reads never consult the oracle.
- Offline: strict mode = no mutations during partition.
- Bootstrap: §7 — TOFU registration + operator approval + oracle pin.
- Control-plane compromise: out of scope (I); mitigations §11.
- Network failure: J — fail closed.

Verdict: meets the independence requirement with no hardware
assumption. The only option that does.

### Option D — Signed remote checkpoint

C with the checkpoint as a self-verifying signed object. Signature
purposes (§5): domain authentication to the oracle, transit/storage
integrity, audit non-repudiation. It does NOT prevent journal forgery —
the gateway faithfully checkpoints whatever its journal contains.

### Option E — External append-only receipt anchoring

Receipts prove "the gateway said X" — existence, not *latestness*.
Monotonicity still needs compare-and-store semantics = Option D's
oracle. Receipts are the checkpoint **audit transport** only:
observability, zero authority role. No circular dependency — receipts
consume checkpoint output, never gate authority. A receipt must never
be treated as an anti-rollback anchor because it contains a hash.

### Option F — Hybrid

**Recommended (§14)**: local journal + signed-checkpoint oracle (C+D),
receipt trail for observability (E), optional TPM as a third tier (B).

## 7. Bootstrap — including AM-3 ORACLE IDENTITY PIN

### 7.1 The two trust directions are separate

- **Oracle authenticates the gateway checkpoint**: signature over the
  checkpoint under a key in the domain's registered lineage.
- **Gateway authenticates the oracle**: a pinned oracle identity —
  REQUIRED. "Connect to whichever oracle answers" is forbidden in
  strict mode.

### 7.2 Oracle identity pin (AM-3 — mandatory)

- **Format**: oracle public identity = Ed25519 pubkey (hex) or TLS
  certificate fingerprint, carried in config as `gateway_anchor_pin`.
- **Storage**: gateway config file — operator-written, outside the
  replaceable registry (config pins follow the existing
  `trusted_issuers`/TOFU-pin convention).
- **Provisioning**: operator sets it at domain provisioning, from the
  oracle's out-of-band-published identity. Same ceremony as TOFU pins.
- **Rotation**: oracle key/cert rotation is itself an operator event —
  new pin distributed out-of-band; old pin rejected immediately after
  cutover (fail closed, loud).
- **Mismatch**: REFUSE channel + fail closed in strict mode — the
  gateway must not accept checkpoint answers from an unpinned peer.
- **Bootstrap**: pin must exist before `anchor_mode=strict` is set;
  strict mode with no pin fails startup validation.
- MITM impact if unpinned: bounded (fake-new A → refuse = availability;
  A_old → self-heal) — but the pin is mandatory anyway because failure
  semantics must be unambiguous.

### 7.3 Domain bootstrap (first checkpoint)

1. Gateway first boot → registry created (0600), key minted, gw_id
   enrolled. No anchor exists.
2. First authority transition emits checkpoint #1 and pushes it.
3. **Oracle registration**: first checkpoint accepted only for an
   unregistered domain_id over the gateway's PoP-authenticated channel —
   domain_id ⇄ key lineage is TOFU'd at the oracle.
4. **Operator confirmation (REQUIRED)**: `gwctl anchor-status` prints the
   oracle's registered `{domain_id, genesis tip_hash, active key
   fingerprint}`; the operator compares it out-of-band against
   `gwctl`'s local `{enrollment id, key fingerprint, journal tip}`.
   The artifact compared is the (domain_id ⇄ pubkey fingerprint) pair.
5. Attacker-as-first-authority: first-write-wins per domain. If an
   attacker registers first, the real gateway's registration conflicts
   → refusal + alert. Skipped operator confirmation degrades the
   property to detectable-failure — never to silent compromise.
6. Deliberate rollback / restore-from-backup: reset ceremony — operator
   generates a signed reset token via `gwctl anchor-reset` (operator
   credential, not gateway credential); oracle accepts seq-reset only
   with it. Absent the token, reset = refusal.
7. Pre-P2.3.3 journals: migration — §15, AM-5.

## 8. Recovery matrix — including AM-2 CO-ROLLBACK ROWS

Notation: `L` = local journal tip `(seq, hash)`, `A` = oracle-stored,
`W` = last-seen anchor watermark recorded in the journal
(observability aid — distinguishes clean crash-recovery from oracle
regression; NOT a security boundary, it rolls back with the journal).

### 8.1 Journal-vs-oracle reconciliation

| Case | Decision |
|---|---|
| L == A | ALLOW |
| L.seq > A.seq, chain valid | RECOVER — re-push current tip (contiguity not required); W == A → clean crash-recovery; W > A → oracle regressed → ALERT |
| L.seq < A.seq | DENY — rollback detected; operator reset ceremony or re-provision |
| L.seq == A.seq, hash ≠ | DENY + ALERT — corruption/forgery |
| Oracle unavailable at mutation | DENY the mutation (strict); journal unchanged |
| Oracle unavailable at boot | DENY trust-init (strict) — §11 |
| Oracle unavailable while running | ALLOW — reads never consult oracle |
| Oracle corrupted/unparseable | DENY + ALERT — oracle-side recovery |
| Conflicting checkpoint (same seq, diff hash) | DENY + ALERT — split-brain/attack signal |
| Oracle returns OLDER checkpoint | same as L>A — RECOVER via re-push (+ ALERT if W > A) |
| Oracle returns NEWER than local history | DENY — local journal older than authoritative history |
| Key rotation (normal) | ALLOW — dual-signed rotation checkpoint advances oracle lineage |
| Consumed grant / retired gw after restore attempt | DENY via L<A — the point of the design |

### 8.2 AM-2 — Backup/co-rollback matrix (normative)

| Registry | Oracle | Decision |
|---|---|---|
| restored | intact | DENY — L.seq < A.seq, rollback detected |
| intact | restored (older store) | RECOVER — L.seq > A.seq → re-push re-establishes the ceiling; ALERT if W > A shows the oracle regressed |
| restored | restored to SAME checkpoint | ALLOW only if consistent (L == A) — an operational restore, not an attack surface distinction |
| restored | restored to OLDER checkpoint | DENY — L.seq > A.seq is recoverable BUT the pair state is suspect: if L itself is a rollback, L<A wins → DENY. Consistent-pair analysis below |
| restored | restored to NEWER checkpoint | DENY — L.seq < A.seq |
| **both restored to a mutually-consistent historical backup** | | **UNDETECTABLE — anchor-compromise / trusted-backup-compromise residual.** The pair is internally consistent; no mechanism inside the composition can refute it. Named explicitly; mitigated ONLY by independent durability schedules (AM-6) |
| oracle backup unavailable | n/a | oracle cannot serve → strict: DENY mutations/boot; oracle ops restore required |
| oracle backup corrupted | n/a | DENY + ALERT — oracle-side recovery; never silently re-initialize an empty anchor (that would erase the ceiling = self-inflicted rollback) |

**Normative**: restoring the oracle from an older backup is NOT ordinary
crash recovery — it is an **authority-recovery event** and must be
treated as one (operator-visible, alerted, never silent). The oracle
does NOT prevent rollback when the attacker can restore the oracle's
authoritative state itself — that scenario is out of scope by
definition (I) and must remain stated, not softened.

## 9. Checkpoint data model — AM-4 FIELD TRIM + CANONICALIZATION

### 9.1 Signed security-critical fields (the ONLY signed fields)

| Field | Class | Purpose |
|---|---|---|
| `version` | required for canonicalization | format version — prevents cross-version reinterpretation |
| `domain_id` | security-critical | binds checkpoint to exactly one authority domain (R6) |
| `seq` | security-critical | journal sequence — THE monotonic value |
| `tip_hash` | security-critical | SHA-256 chain hash binding the entire journal prefix |
| `key_id` | security-critical | identifies the signing key for lineage checks |
| `sig` | security-critical | Ed25519 signature over the canonical encoding of the above |

**Removed** (no security purpose): `checkpoint_seq` (redundant — journal
`seq` IS the monotonic value; retained only as oracle-side dedup
metadata, unsigned), previous-checkpoint reference (the journal chain
already binds history — a second chain is redundant), `authority state`
(derivable — never anchor derivable state), `timestamp` (informational
only — **wall-clock time is never an anti-rollback primitive**),
`gw_id` (informational/audit — may ride unsigned alongside).

### 9.2 Canonical serialization — normative

Same `lp()` framing as frozen PoP canonicalization:

```
checkpoint_preimage =
    lp("OVARA-ANCHOR-CP-V1")
    || lp(domain_id)
    || lp(u64be(seq))
    || lp(tip_hash_raw_32B)
    || lp(key_id)
sig = Ed25519.Sign(priv, checkpoint_preimage)
```

The same logical checkpoint produces exactly one canonical signed
representation — fixed field order, length-prefixed binary, no JSON
serialization ambiguity. `u64be(seq)` fixes integer encoding.

### 9.3 Journal chain (AM-4 companion)

Each journal record gains `seq` and `chain` fields:
`chain_n = SHA-256(chain_{n-1} || canonical_json(record_n))`, genesis
over `domain_id`. `tip_hash` at seq N binds the whole prefix: mid-file
modification (threat D) breaks the chain locally — detected without
the oracle; truncation/restore yields seq < A.seq or mismatched tip —
detected by the oracle.

## 10. Cryptographic trust model — AM-1 completion

- Hash: SHA-256. Signatures: Ed25519 (frozen P2.3.1 infrastructure).
- Signing key: gateway's active key — **its home is `var/data/`,
  protected only by 0600.** The honest bound (§3.3): R7 holds against
  the registry-file attacker; the directory attacker can sign — but
  still cannot decrement the oracle. For directory-attacker
  deployments, an anchor-dedicated key outside `var/data/` is an
  available hardening option, not required for the core claim.
- Lineage: rotation checkpoint dual-signed by retiring + new key during
  the existing grace window; oracle advances accepted lineage.
- Oracle identity: gateway pins it (§7.2) — mandatory.
- Trust root: operator — confirms registration, holds reset credential,
  provisions the oracle pin.
- **Circularity check**: the oracle never reads the registry — it
  compares signed seqs. Lineage trust is TOFU'd at genesis (no history
  exists to roll back) and operator-confirmed. The dangerous circularity
  (oracle trusting the current registry to decide authority) does not
  exist. PASS.
- Replay: oracle stores max(seq); replayed checkpoint has seq ≤ stored
  → rejected (R5). Freshness: seq only, never timestamps.

## 11. Failure modes — including AM-6 ORACLE DURABILITY

### 11.1 Oracle store durability (AM-6 — normative requirement)

"Durable" is a **security requirement**, not an ops nicety. The oracle's
monotonic state MUST survive process restart, machine restart, power
loss, and crash recovery without silently reverting to an older
checkpoint. In-memory max(seq) is NOT sufficient — a restart that
forgets the ceiling is a silent authority rollback.

Required of the oracle's store:

- **Persistent storage**: append-only or single-record-per-domain file
  on the oracle's own filesystem (Tier-1: separate-uid dir; Tier-2:
  oracle host).
- **Atomic update**: write-temp + rename (or single-sector append) —
  no torn checkpoint may ever be served.
- **fsync boundary**: the PUT ack is issued only after the new max is
  fsync'd — the gateway treats ack as durability proof.
- **Crash recovery**: on restart the oracle reloads its durable state;
  a corrupted tail truncates to the last complete record (same rule as
  the gateway journal).
- **Backup policy**: the oracle's store MUST be durable on an
  **independent schedule/medium from gateway backups** — this is what
  keeps the co-rollback residual (§8.2) an edge case rather than the
  default backup topology.
- **Restore policy**: restoring the oracle store from backup is an
  authority-recovery event — operator-visible, alerted, and NEVER a
  silent empty re-initialization (an empty anchor erases the ceiling =
  self-inflicted rollback).

### 11.2 Other failure modes

- **Oracle down**: mutations fail closed; reads unaffected; running
  gateway keeps serving already-committed state. Boot under strict
  refuses trust-init (operator override flag writes a journal record —
  auditable, never silent).
- **Oracle compromised**: out of scope; mitigations: signed checkpoint
  trail + receipt events expose tampering after the fact; conflicting-
  checkpoint detection alerts.
- **Gateway key compromise**: forward-hijack only — §3.3.
- **Clock skew**: irrelevant — no time in the security path.
- **Split-brain** (two gateways, one domain): seq collision → second
  writer rejected + alert. Single-winner.

## 12. Tier security model — PART C (per-tier claims, labeled)

| | Tier 1 — local separate-UID oracle | Tier 2 — remote oracle | Tier 3 — TPM (optional) |
|---|---|---|---|
| Registry-file attacker | DEFEATED | DEFEATED | DEFEATED |
| Directory attacker (has gateway key) | rollback DEFEATED; forward-hijack residual | same | same |
| Root / full host attacker | **NOT defeated** — oracle store replaceable | DEFEATED (assuming oracle trust root + network auth uncompromised) | **DEFEATED** — the only local mechanism that survives root |
| Oracle compromise | out of scope | out of scope | TPM owner-hierarchy compromise = out of scope |
| Availability on partition | none (local) | strict: mutation/boot downtime | none (local) |
| Deployment cost | one daemon + one dir | service + channel auth + pin | hardware + provisioning ceremony |

**Tier-3 precise contribution**: TPM adds *host-attacker survival* —
an increment-only NV counter is the one anchor a root attacker cannot
decrement. It adds nothing over the oracle for the scoped model, and it
is NOT mandatory unless the threat model requires single-host root
resistance. TPM never substitutes for the oracle's "latest" answer; it
only proves "epoch ≥ N" locally.

## 13. Co-rollback security claim — PART D (precise language)

The system provides:

> **Local registry rollback resistance when the oracle's authoritative
> state survives.**

It does NOT provide:

> Rollback resistance against an attacker who can restore BOTH the
> registry AND the oracle's authoritative state to a mutually-consistent
> older checkpoint.

That scenario is an **anchor-compromise / trusted-backup compromise** —
out of scope (I), named here so no downstream document can claim
otherwise. "Secure within the composed anchor model" ≠ "secure against
anchor compromise" — the two are different properties.

## 14. Recommended architecture

**Option F = C+D(+E transport)(+B optional):**

- Journal gains `seq` + `chain` (§9.3) — migrated one-way (§15).
- Oracle: minimal service exposing `PUT /v1/anchor/{domain}` (verify
  pin-bound channel + checkpoint signature; accept seq > stored, or
  seq == stored with identical tip_hash as idempotent retry; reject all
  else; ack only after fsync — AM-6) and `GET /v1/anchor/{domain}`
  (return stored checkpoint). Oracle-side state: exactly
  `(domain_id → seq, tip_hash, accepted key lineage)` — nothing more.
- Gateway `mutate()` gains fsync → push → ack → return (strict);
  `gateway_anchor_mode = strict|degraded|off` (`off` = P2.3.2 behavior,
  documented weaker). Boot reconcile per §8 inside `initGatewayTrust`.
- `gateway_anchor_pin` config — mandatory in strict mode (§7.2).
- Receipt service receives checkpoint events (audit); TPM NV epoch
  optional via a tiny `Anchor` interface, oracle primary.

Smallest architecture that establishes a real independent boundary:
one endpoint pair, one signed message type, two journal fields.

## 15. Migration from P2.3.2 — AM-5 OPERATOR ATTESTATION

Migration is an **attestation event, not a forensic one** — the design
MUST NOT assume the current registry is automatically authoritative.

### 15.1 Procedure

1. `anchor_mode=off` ships first — zero behavior change.
2. `gwctl anchor-init --attest` run by the operator (operator token —
   operator identity = the same fs-authority root as gwctl today).
3. The tool prints the **attestation artifact**: `{journal tip seq,
   chain hash, total records, per-gateway summary (active keys,
   retired tombstones), grant summary (authorized/consumed/denied
   counts)}`.
4. The operator inspects and **explicitly confirms** this is the
   current authoritative state (out-of-band knowledge of the
   deployment — they know what they retired and granted).
5. On confirmation: seq + chain assigned in file order, a
   `kind:"migrate"` marker appended (never rewrite lines — append-only
   evidence preserved), genesis checkpoint emitted, domain registered
   at the oracle.
6. `anchor_mode=strict` set; oracle pin verified present first (§7.2).

### 15.2 Edge cases — all fail closed

| Condition | Decision |
|---|---|
| Migration state ambiguous (operator cannot confirm) | DENY — no checkpoint emitted; migration aborts |
| Registry corrupt/unparseable | DENY — repair or re-provision before anchoring |
| Conflicting grant/key records in journal | DENY — the journal fails closed on load already; a journal that can't fold can't be anchored |
| Gateway already retired | allowed to anchor — tombstone state is the anchored tip; retirement finality preserved from genesis |
| Active keys present | anchored as current lineage — normal |
| Consumed grants present | anchored as consumed — their terminality is exactly what genesis protects going forward |
| Registry already rolled back pre-migration | **UNDETECTABLE by design** — attestation legitimizes present state; the operator's confirmation is the only guard. Stated limit. |
| Anchor already exists for domain | DENY — re-registration is the reset ceremony (§7.6), not init |

**Normative**: migration fails closed whenever initial authoritative
state cannot be established. A migration that "best-effort anchors"
would legitimize unknown history — the worst outcome.

## 16. Why the alternatives were rejected

- **A alone**: no independence — same replaceable filesystem.
- **B alone**: no TPM on most of the embedded fleet; kept as Tier-3.
- **E alone**: receipts prove existence, not latestness; audit
  transport only.
- **Local hash-chain alone**: proves tampering, not newest — the oracle
  is the missing comparator.
- **Signed journal records**: solves forgery, not rollback — fs write
  already concedes authority.
- **Full external journal**: heavier than needed; tip-hash binding
  suffices (R13); gateway-side storage retained.

## 17. Security invariants

- **R1** authority history cannot move backwards — oracle max(seq).
- **R2** consumed grant cannot become pending again — via R1.
- **R3** retired gateway cannot become active again — via R1.
- **R4** restored registry cannot increase authority — restore is
  strictly older; fabricated-newer cannot reclaim oracle-recorded
  terminal states.
- **R5** old checkpoint cannot be accepted as newer — seq ≤ stored
  rejected.
- **R6** checkpoint bound to exactly one domain — domain_id signed +
  oracle keying.
- **R7** attacker-controlled registry cannot forge a newer checkpoint —
  holds for registry-file attacker; directory attacker degrades to
  forward-hijack (availability), never rollback (§3.3).
- **R8** crash cannot produce two valid histories — fsync-then-push +
  oracle uniqueness per (domain, seq).
- **R9** required oracle failure fails closed — strict mutation/boot
  refusals; degraded mode never silent.
- **R10** bootstrap cannot be attacker-controlled — PoP channel +
  first-write-wins + operator confirmation.
- **R11** gateway rollback cannot roll back oracle state — no
  regression channel exists (compare-and-store rejects).
- **R12** oracle rollback cannot silently roll back authoritative
  state — gateway re-push restores the ceiling; joint co-rollback is
  the named residual (§13).
- **R13** journal prefix integrity oracle-free — chain hash detects
  mid-file modify locally.
- **R14** no silent authority-mode change — degraded/override
  transitions journal-logged and loud.
- **R15** (AM-6) oracle monotonic state is durable — no ack before
  fsync; restore-from-backup is an authority event, not crash recovery.

## 18. Attack scenarios (walk-throughs)

1. Snapshot-restore grant replay → L.seq < A → REFUSE. Dead.
2. Snapshot-restore resurrection → same → REFUSE. Dead.
3. Prefix-truncate + restart → tip seq < A → REFUSE.
4. Aligned rewrite (prefix intact) → forward appends = conceded
   fs-authority; checkpoint advances; no rollback occurred.
5. Kill between fsync and push → L > A at boot → re-push → ALLOW.
6. Replayed old checkpoint → seq ≤ stored → rejected.
7. Conflicting checkpoint (clone/split-brain) → second rejected +
   ALERT; stored history unrewritable.
8. Oracle row deleted/corrupted → out of scope (anchor compromise);
   signed receipt trail exposes the gap.
9. Oracle outage + restore during degraded window → undetectable —
   the documented degraded cost; strict kills it by refusing boot.
10. Key theft → forward-hijack only; rollback still dead (§3.3).
11. Joint registry+oracle restore to consistent old state →
    UNDETECTABLE — §13 residual.
12. MITM impersonating oracle → pinned identity refuses (§7.2); even
    unpinned, worst case is availability, not regression.

## 19. Test strategy

- Unit: chain-hash vectors (modify any record → detect), canonical
  checkpoint round-trip (same input → byte-identical preimage),
  sign/verify, seq ordering, §8 matrix as table tests, dual-sign
  rotation lineage, reset-token verify, oracle-pin mismatch refuse.
- Fault injection (p232-style harness + mock oracle):
  restore-pre-consumption (dead), restore-pre-retirement (dead),
  truncate+restart (dead), kill fsync↔push (re-push), oracle outage
  at mutation (refuse) / at boot (strict refuse), replayed checkpoint
  (reject), conflicting checkpoint (reject+alert), forged signature
  (reject), split-brain (single winner), oracle-restart durability
  (survives), oracle-store-restore (recover-or-refuse per §8.2),
  degraded window (documented bound).
- Regression: all P2.3.2.1 suites re-run with anchor off (= frozen
  behavior) and strict (= superset). No test weakened.
- Race: concurrent mutations serialize via flock → sequential pushes;
  concurrent admit keeps exactly-one-winner.

## 20. Security claim matrix (target state, strict mode)

| Claim | Status |
|---|---|
| Torn-tail recovery | VERIFIED (unchanged) |
| In-process shrink detection | VERIFIED (unchanged) |
| Journal prefix integrity (record modify) | VERIFIED — chain hash, oracle-free |
| Journal completeness | VERIFIED (unchanged fold) |
| Rollback resistance — consumed grant replay | VERIFIED — oracle max(seq), when oracle state survives |
| Rollback resistance — retirement resurrection | VERIFIED — same |
| Rollback resistance — prefix truncation | VERIFIED — same |
| Joint registry+oracle co-rollback | NOT PROVEN — anchor-compromise residual (§13) |
| Aligned rewrite / forward forgery | ARCHITECTURAL LIMITATION — fs write = authority |
| Forward-hijack via stolen gateway key | ARCHITECTURAL LIMITATION — availability risk, not rollback (§3.3) |
| Retirement finality | VERIFIED (upgrade from PARTIALLY) |
| Grant replay protection | VERIFIED (upgrade from PARTIALLY) |
| Anchor availability | PARTIALLY VERIFIED — strict = fail closed; partition = mutation/boot downtime |
| Oracle durability | VERIFIED per AM-6 spec — fsync'd before ack |
| Anchor compromise | NOT PROVEN — out of scope; §11 mitigations |
| Bootstrap integrity | VERIFIED under operator-confirmed TOFU + oracle pin; detectable-failure if confirmation skipped |
| Domain isolation | PARTIALLY VERIFIED — domain_id signed into checkpoints; file still defines membership |

## 21. Open questions

1. Oracle placement: standalone service vs endpoint on an existing
   control-plane service — decide by deployment shape; the protocol is
   identical either way.
2. Oracle store durability topology: replication vs independent
   snapshot policy — ops decision, required explicit (AM-6).
3. Offline-only deployments with no network path and no TPM: accept a
   documented "no rollback resistance" tier or mandate hardware?
4. Reset-credential strength: same fs-authority as gwctl, or a
   distinct operator factor for anchor-reset?
5. Directory-attacker deployments: anchor-dedicated key outside
   `var/data/` — worth the extra file?
6. Multi-writer domains (future): writer-id dimension needed if two
   gateways ever share one domain.

---

*Amended per architecture review: AM-1 key-boundary scoping (§3),
AM-2 co-rollback matrix (§8.2), AM-3 oracle identity pin (§7.2),
AM-4 checkpoint field trim + canonicalization (§9), AM-5 migration
attestation (§15), AM-6 oracle durability (§11.1), tier model (§12),
co-rollback claim (§13). Implementation deferred pending design freeze.*

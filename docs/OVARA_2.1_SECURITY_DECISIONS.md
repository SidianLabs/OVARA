# OVARA 2.1 — SECURITY DECISIONS

Phase A decisions, grounded in the inspected code. Each entry states the
decision, its basis in the actual implementation, and the security
consequence. Items needing operator/product approval are marked
**OPEN**.

## D1 — Signed journal activation rule (RESOLVED)

Decision: signed journals activate per-store when the store is file-backed
AND durable gateway identity is configured (`gateway_key_file` +
`gateway_registry_file`).

Basis: `domain_id` derives from the gwidentity first line, and `key_ref`
resolution needs the durable registry. Without durable identity, no
durable domain exists to bind signatures to — signing against an ephemeral
domain adds bytes, not security.

Consequence: `ovara init` now writes `gateway_key_file` +
`gateway_registry_file` + the authority file paths so a default deployment
is durable-signed rather than silent memory-mode. Deployments that
override to memory-mode get exactly 2.0 guarantees (documented degraded
mode — not silently weaker, the degraded list is printed at boot).

A `journal_signing_required` config flag forces fail-closed for hardened
deployments: any authority `*_file` without durable identity = boot error.

## D2 — Tip-ledger cadence (RESOLVED)

Decision: ledger = committed **floor**. Writes happen (a) after every
authority-store mutation batch (piggybacked on the store's own fsync
ordering — the tips write strictly follows the covered fsync), and (b) a
ratchet at store open covering any newer tip.

Basis: alternatives considered — per-record ledger fsync on a timer
(amortized) leaves a window where committed state is unledgered and
complicates "is this tail committed"; open-only ratcheting lets a long
uptime stretch accumulate unledgered state but adds no exposure since the
store's own chain authenticates the tail. Mutation-coupled writes are one
extra fsync per mutation — same cost class as the store's own write; the
journal is already in the latency path.

Consequence: honest crashes can only produce store ≥ ledger (never
store < ledger), so the open-time rule "behind → refuse" cannot false-
positive on a crash — provided the write ordering is held: **tips records
are written only after the covered mutation's fsync returns.**

## D3 — Unledgered tail handling (RESOLVED)

Decision: a store tip ahead of the ledger is **authentic-but-uncommitted**
— it loads (its own sig+chain prove authenticity), the ledger ratchets
forward at open, and the records become fully authoritative once the
ratchet lands.

Basis: the ledger's job is truncation detection, not commit gating —
gating would make every crash brick the gateway (availability DoS by
power loss). Records past the floor are still signature-verified.

Consequence: an attacker truncating to below the floor is caught; an
attacker truncating store AND ledger identically rolls both back
consistently — bounded by the anchor floor (the gwidentity journal
carrying tips is itself anchored; anchor reconciliation detects
gwidentity-side truncation). Whole-domain atomic rollback remains an
oracle-level limitation — unchanged, documented.

## D4 — Lease expiry at claim (RESOLVED — implement)

Confirmed: `CheckClaimAuthority` re-checks revocation only; lease `Expiry`
and delegation-hop `ExpiresAt` are validated at eval only.

Decision: `Continuation.authority_expires_at` = `min(lease.Expiry,
terminal-hop ExpiresAt)` — captured server-side at `handleCreate`,
immutable in the fold, deny-direction check inside `CheckClaimAuthority`
before the revocation check. Signature and claim ordering unchanged.
Executables whose authority expired between eval and claim transition to
`denied` (terminal), never execute.

## D5 — Policy freshness (RESOLVED — not implemented this phase)

Inspected: `Policy` carries `policy_version`/history; approvals bind
`PolicyVersion` into the record; no claim-time policy check exists;
`watchPolicy` hot-reloads but never revalidates pending work.

Current semantic (code): **"policy at evaluation time"** — the receipt
binds the eval-time version. Nothing in code or docs promises validity at
execution time.

Decision: keep eval-time semantics; DO NOT add `policy_epoch` in this
phase. Rationale: it is a new frozen-surface semantic (an approved
continuation could be killed by a later policy edit — a new deny vector
and a product-level semantics change). Documented as an **OPEN** product
decision:

- Model A (current): eval-time binding. Approved work survives policy
  tightening until its own expiry. Simple, honest.
- Model B (execution-time): claim re-checks policy version/evaluation.
  Stronger revocation surface; needs a policy-history lookup at claim and
  a definition of "tightened" (version mismatch vs semantic conflict).

## D6 — C2 boot attestation (DEFERRED pending approval)

Bootstrap inputs (`config.json`, `policy.json`, `proxy.json`,
`trusted_issuers`) remain plaintext trust roots — the bootstrap-laundering
class from the adversarial review is unchanged this phase. The trust
boundary is documented: *an attacker who can write the bootstrap config
owns the domain until the attestation phase lands.*

If approved later: a signed `boot_attestation` gwidentity record at
startup hashing each configured bootstrap input; drift becomes
**detectable** (never preventive).

## D7 — Migration (RESOLVED)

Per §7 of the journal spec: identity/capabilities/enrollment import under
operator attestation (`gwctl migrate`); continuation/approval/execution
files are quarantined (`.pre21`), not imported — drain-or-expire. Old-file
hash proves provenance, not honesty. Single-genesis enforced by fold.

## D8 — Compaction/tombstones (RESOLVED)

Terminal facts survive compaction via tombstone records (spec §8).
Existing `_cleanup` deletion records are replaced by signed `compact`
events; unsigned ones are fold errors. Replay/revocation keep their
existing compaction shape (append-only, no per-record state) under the new
envelope.

## D9 — Decision journal (RESOLVED — reuse receipts)

The design's "decision journal" is the journaled receipts store: each
receipt record already carries `decision_id`, `request_hash`,
`policy_version`, `verdict`, `capability_lease_id` under `edsig_v1`.
Journalizing the receipts store (per-record envelope + chain + domain)
turns it into the durable decision journal — no new store, no new file
key. `receipt.persist_failed` ordering is untouched.

## D10 — Executor identity gate (RESOLVED)

Both dispatch sites drop the `agent_id != ""` precondition. Empty
`agent_id` → gate fails → deny (record to `denied`, reason
`identity_missing`). Nil `identityChecker` keeps current semantics
(registry not configured = nothing to check) — fail-closed happens inside
the registry path, not by inventing a checker.

## OPEN items needing explicit approval

1. **D6 boot attestation** — defer (recommended) or implement.
2. **D5 policy freshness model** — keep eval-time (recommended) or add
   execution-time recheck (frozen-surface change).
3. **`ovara init` durable defaults** — writing key/registry/authority
   paths by default changes a fresh deployment's on-disk layout
   (recommended: yes — it closes the biggest real-world gap).


## D11 — C2 split + claim-time provenance (RESOLVED scope)

Post-merge C2 evaluation (adversarial suite `adversarial_c2_test.go`)
confirmed **C2-KEY-ROOT**: `gateway.key` is a root-of-authority
credential — a stolen key plus trust-domain write injects validly
signed `queued` records that fold, anchor, and execute without
traversing the approval pipeline. C2 splits:

- **C2-A bootstrap/configuration integrity** — policy.json,
  proxy.json, config.json, operator tokens, `${ENV}` bindings.
  Attestation/signed-config addressable. Open.
- **C2-B signing-root compromise** — NOT addressable by attestation
  alone (a post-attestation key theft still produces indistinguishable
  signatures). Deferred to 2.3 research: key custody (HSM/KMS/sealed
  storage), attested signing contexts, threshold authorization.

**Provenance hardening (implemented, defense-in-depth only):**
`CheckClaimProvenance` runs inside the claim path after revocation —
a claimed continuation must carry `ApprovalID` resolving to an
APPROVED approval record whose decision_id/action_type/resource/
agent_id match. Eliminates the demonstrated empty-authority forge
(one signed record, nothing to evaluate); the attacker must now
manufacture a coherent cross-journal state — still possible under
key compromise, since the same key signs every journal. Claim NOT
made: this bounds C2-B — it does not.

Claims intentionally NOT made: bootstrap-input tamper resistance,
whole-domain atomic rollback, hardware-rooted keys, execution truth,
distributed replay, kill-running-execution. Signing-root compromise:
PARTIALLY claimed (D12) — gateway.key alone can no longer mint
claimable authority, but approver custody is currently same-
filesystem; whole-trust-domain compromise still wins until A2.

## D12 — C2-B Phase A1: dual-root approvals

**Decision.** The approvals journal signs under a SEPARATE root key —
`role=approver` records in the gwidentity registry — when
`approver_key_file` + `approver_pubkey` are configured. Possession of
`gateway.key` alone can no longer mint a claimable continuation.

**The trust decision, in order:**

- `approver_pubkey` is the approver trust root — operator-held,
  bootstrap input (C2-A territory: it must be protected like the rest
  of the unanchored configuration surface).
- `key_ref → registry → KeyRecord exists → role==approver → key
  usable → sig verifies` — role is part of the trust decision, not
  metadata. An attacker-written `role=approver` registry record fails:
  the gwidentity journal is hash-chain-sealed, NOT keyed — so the pin
  is enforced at fold/absorb and at admit. Fold-time rejection is
  fail-closed (store will not open).
- Signing domains are MUTUALLY exclusive: `ResolveApproverKey` only
  accepts envelopes naming the `approver` principal, and the gateway
  resolver refuses `role=approver` records — neither root can forge
  in the other's journal.
- Claim-time `ApproverUsable(SignerKeyID)`: approvals signed under a
  revoked/retired approver key deny at claim (rotation = a kill
  switch for in-flight authority under the old root).
- Stacks on #12's provenance checks — nothing is replaced.

**Demonstrated** (`adversarial_c2b_test.go`, 10 tests): gateway.key +
fs-write cannot produce a claimable continuation; ANCHOR-01-style
forge → fold → claim → PROVENANCE DENIED → no execution; approver
key alone cannot forge in the continuation journal; registry-forged
approver records die against the pin; revoke/rotate both deny.

**What remains (honest):** shared-custody deployment — approver key
in the same directory as `gateway.key` — is cryptographic separation
without custody separation. A2 moves approver custody off-gateway
(control-plane signing / KMS); M5-style confused-deputy hardening is
further research. Enabling an approver root mid-deployment fail-
closes the existing approvals journal (foreign-domain records) —
approver must be on at init or the journal migrated.

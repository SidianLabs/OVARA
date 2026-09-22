# OVARA 2.1 — IMPLEMENTATION PLAN

Phase A output: repository-grounded implementation decisions for the CBDA
hardening program (adversarial-review conditions C1–C6). Analyzed tree:
`devin/1790095116-ovara-21-cbda` = `main@000d70b` + anchor portability split
(verbatim Linux move; darwin `LOCAL_PEERCRED`; other platforms fail closed).

This document was produced by inspecting the code paths enumerated in §3 of
the implementation playbook. Where a statement could not be verified, it is
marked UNKNOWN.

---

## 1. INVENTORY — EVERY AUTHORITY JOURNAL / STORE

Derived from `pkg/server/server.go` store construction and each package's
persistence code. Two dimensions are tracked because the review relies on
each differently:

- **Integrity model** — does the file defend its own contents?
- **Reads by claim path** — is it consulted at eval/claim/approve time and
  can a forged record become executable authority?

| # | Store | Config key | Default | File format | Integrity model | Read at claim time? |
|---|-------|-----------|---------|-------------|-----------------|---------------------|
| 1 | `gwidentity` (gateway key registry + grants + revocations) | `gateway_registry_file` | in-memory | append JSONL, per-line `seq`+`chain` seal, anchored folds | strong: chain + anchor tips | NO (verifies presented PoP/keys) |
| 2 | `idregistry` (identities + credentials + sessions) | `identity_registry_file` | in-memory | whole-file atomic JSON 0600 | **none** (atomicity only) | YES — `bindIdentity` lookup, identity gate |
| 3 | `replay` journal | `replay_file` | in-memory | append JSONL + flock/fsync | ordering only — no hashing; deletion resurrects nonces | YES — `OnceConsume` at eval |
| 4 | `revocation` journal | `revocation_file` | in-memory | append JSONL + flock/fsync | ordering only | YES — `CheckClaimAuthority` |
| 5 | `continuation` store | `continuations_file` | in-memory | append JSONL 0644, last-writer-wins on id, `_cleanup` pseudo-records | **none** | YES — source of claimable state |
| 6 | `approval` store | `approvals_file` | in-memory | whole-file JSON map | **none** | indirect — `ApplyApprovalDecision` |
| 7 | `execution` store | `execution_file` | in-memory | append JSONL | **none** | NO (audit/dedup evidence) |
| 8 | `receipts` store | `receipts_file` | in-memory | whole-file JSON list | record-level `edsig_v1` signature; list itself unsigned | YES indirectly (chain tip, `anchored_seq`) |
| 9 | `events` store | `events_file` | in-memory | append JSONL | none (audit surface) | NO |
| 10 | `anchor` journal (gwidentity anchor client side) | `anchor_*` | disabled | binary seq records + tips | anchor attestation | YES — `anchored_seq` proofs |
| 11 | `capabilities` store | `capabilities_file` | in-memory | whole-file JSON | **none** | NO at claim today (see C4) |
| 12 | `enrollment` store | `enrollment_file` | in-memory | whole-file JSON | none | NO |
| 13 | decision journal | none — **does not exist** | — | — | — | — |
| 14 | `trusted_issuers` | `config.json` | — | plaintext config | none | YES — eval delegation root |
| 15 | `operator_tokens`, `policy.json`, `proxy.json` | — | — | plaintext | none | YES — operator root / policy |

**Ledger coverage decision (C1):** tip-ledger binds every store that either
(a) can mint executable authority — 5, 6, 2, 13 — or (b) is consulted at
claim/eval to keep authority dead — 3, 4, 8. Stores 7, 9, 12 are
advisory/audit: signing is desirable but they are not on the claim path;
they enter the ledger at Phase 2 anyway because an unledgered authority
store is the documented escape hatch (§5 strict rule). `config.json`,
`policy.json`, `proxy.json`, `trusted_issuers` are *bootstrap inputs*, not
journals — they are handled by the C2 boot-attestation boundary (deferred)
and remain a documented trust root.

---

## 2. EVERY LOAD / FOLD PATH

| Store | Function | File |
|-------|----------|------|
| gwidentity | `Registry.Open` → per-line `json.Unmarshal` → `chainFoldLine` verifies `seq`, `chain` = sha256(prev_line || canonical(rec)); `domainID` = `sha256("OVARA-ANCHOR-DOMAIN-V1" \|\| firstLine)` | `internal/gwidentity/{store,chain}.go` |
| idregistry | `Open` → `json.Unmarshal` whole `fileState` → `normalize` | `internal/idregistry/registry.go:130-180` |
| replay | `Open` → flock → per-line decode → skip malformed | `internal/replay/store.go` |
| revocation | `Open` → same pattern as replay | `internal/revocation/store.go` |
| continuation | `load` → per-line decode → skip malformed; `_cleanup` pseudo-records delete ids; last-writer-wins on `continuation_id` | `internal/continuation/file_store.go` |
| approval | `Open` → whole-file JSON decode | `internal/approval/store.go` |
| execution | `Open` → per-line decode | `internal/execution/file_store.go` |
| receipts | `Open` → whole-file JSON list decode; per-record sig verified lazily | `internal/receipts/store.go` |
| capabilities | `Open` → whole-file decode | `internal/capabilities/file_store.go` |

**Failure posture today:** replay/revocation/continuation/execution skip
malformed lines silently (fail-OPEN on mid-file corruption — violates §14);
gwidentity fails closed on chain mismatch; whole-file stores fail closed
only on unparseable JSON, not on substitution.

---

## 3. EVERY APPEND / MUTATION PATH

| Store | Function | Integrity applied today |
|-------|----------|------------------------|
| gwidentity | `Registry.mutate` → `sealRecord(rec, seq, chain)` → append line → fsync | seq+chain seal per line |
| idregistry | `mutate` → clone → fn → normalize → `persist.WriteFileAtomic(0600)` | none |
| replay | `Append` → flock → write line → fsync | none |
| revocation | `Append` → same | none |
| continuation | `persistLocked` → rewrite **entire** file or append? — see note | none |
| approval | `persistLocked` → whole-file rewrite | none |
| execution | `persistLocked` → append line → fsync | none |
| receipts | `persistLocked` → whole-file rewrite | none |

NOTE (verified): `continuation` `persistLocked` appends one JSONL line per
mutation (`create`, `update` write a full snapshot of the record; terminal
facts are first-class fields, not events). `_cleanup` records are written by
the retention pass. The record IS the state — this is exactly the
event-as-snapshot model the 2.1 journal spec formalizes and signs.

---

## 4. EVERY CLAIM PATH

Claim boundary = `ClaimForExecution` (atomic persisted transition in the
store) followed by handlers-side gates. Two entry points:

1. `handleClaim` → `st.ClaimForExecution(id, executor)` →
   `h.identityChecker` → `CheckClaimAuthority` → `executor.Execute`
   (`internal/handlers/orchestrator.go:191` identity gate, `:305` dispatch)
2. `handleApprove` → `ApplyApprovalDecision` → queues continuations →
   consumed later by the SAME claim path in `handleClaim`.
   `internal/handlers/continuations.go:547` mirrors the identity gate and
   `:611` is the second executor dispatch.

`CheckClaimAuthority` (verified, `internal/continuation/revocation.go:31-52`):
re-checks `revocation.AnyRevoked(PairsFor(LeaseID, DelegationKeys, Issuers))`
only. **Lease expiry is NOT re-checked** (case A in the playbook). Lease
`Expiry` lives on `models.CapabilityLease`; chain hop expiry on
`Authority.ExpiresAt`; the continuation currently records only the *IDs*
(`LeaseID`, `DelegationKeys`, `Issuers`).

---

## 5. EXECUTOR DISPATCH SITES

Exactly two, both verified:

- `internal/handlers/orchestrator.go:305` — after `if h.identityChecker != nil && cnt.AgentID != ""` at :191
- `internal/handlers/continuations.go:611` — same pattern at :547

C3 fix site = both gate conditions. Executor-bound dispatch requires a
non-empty, registry-valid `agent_id`; empty must fail closed (deny-direction
— the record transitions to denied with `identity_missing` reason, or fails
the claim; per §6 the smallest correct change keeps `ClaimForExecution`
semantics and rejects at the gate).

---

## 6. GATEWAY IDENTITY JOURNAL

`internal/gwidentity/` — chained journal (`sealRecord`), record kinds:
`KeyRecord` (state transitions), `GrantRecord` (`"kind":"grant"`),
`RevokeRecord` (`"kind":"revoke"`). `domainID` derived from the first
physical line. `LoadOrCreateKey` (0600 hex ed25519) in `keyfile.go` is the
signing root for ALL 2.1 journal signatures — one key, many stores; the
`key_ref` = `{gateway_id, key_id}` resolved via `ResolveVerifyKey` (which
keeps historical rotated keys verifiable).

**Additive change:** new journal kind `"tips"` — `TipsRecord{Kind, Seq,
Chain, GatewayID, IssuedAt, Tips: map[string]TipDigest}` where
`TipDigest{StoreSeq, TipHash}` — appended by a ledger writer. Fold:
indexGrant-style; last `TipsRecord` wins per gateway_id.

---

## 7. ANCHOR / ORACLE

`internal/anchor` client + `runtime/anchor-service` — seq-anchored fold of
the gwidentity journal. `reconcileAnchor` is a **frozen table**
(`pkg/server/server.go`) — anchor state decisions are not touched. Tip-
ledger records become part of what the anchor anchors: the anchor
authenticates the ledger by construction (no new oracle semantics needed —
this is the deliberate design; the ledger rides inside the already-anchored
journal).

---

## 8. RECEIPT ENVELOPE

`internal/receipt/edsigner.go` — `edsig_v1`: payload = canonical
framed fields, `sig = ed25519(domain || canonical(payload))`. The 2.1
record envelope reuses this convention (same signer shape, new domain
strings `OVARA-RECORD-<type>-V1`, `key_ref` resolved via gwidentity).
`receipt.persist_failed` ordering (F-01) is untouched.

---

## 9. MIGRATION

**No migration implementation exists** — grep confirms only doc/test
mentions. New: `internal/migrate` + `gwctl migrate` subcommand. Semantics:

- Unsigned authority records CANNOT be silently trusted. Two-state rule:
  - store file absent/empty → signed genesis record (v2.1)
  - store file present with unsigned lines → `strict`: REFUSE with operator
    error pointing at `gwctl migrate`; `migrate` writes a `migration`
    genesis record `{old_file_sha256, operator attestation, imported_ids}`
    and re-emits each unsigned record as an imported signed record.
- Identity registry (whole-file): migrate emits `identity_import` records
  per credential/identity — **operator-attestation boundary**, documented.
- Continuations/approvals: per adversarial-review decision — NOT imported;
  drain-or-expire. Unsigned continuation file → refuse-to-load, operator
  drains (let queued work expire) or explicitly migrates via ceremony.
- MIG-01: second migration for same store = illegal (single-genesis rule).

---

## 10. COMPACTION

Existing: `replay` rewrite-in-place compaction; `continuation` retention
(maxRecords / retention days) emits `_cleanup` deletion records — today
these CAN erase terminal facts.

2.1 rules:
- terminal tombstones are retained: `denied|expired|executed|cancelled`
  records prune their *payloads* but never their existence — tombstone =
  `{type:"tombstone", record_id, state, parent}` so the fold still sees
  terminality.
- `_cleanup` pseudo-records become signed `compact` events; unsigned
  `_cleanup` lines are rejected.
- COMPACT tests per playbook §15.

---

## 11. POLICY VERSIONING

`internal/policy` — `policy_version`/`epoch` on `Policy`; hot reload via
fsnotify (`watchPolicy`); `history` store records versions; approval binds
`PolicyVersion` into the record. **No claim-time policy check exists.**
Current semantics (docs + code): **"policy at evaluation time"** — the
decision receipt binds `policy_version` at eval; nothing promises the
policy is still valid at execution. Decision documented in
`OVARA_2.1_SECURITY_DECISIONS.md` — policy_epoch is NOT implemented in this
phase (would be a frozen-surface semantic addition requiring approval).

---

## 12. LEASE VALIDATION

Eval-time: `internal/identity/validator.go` — `expiry required + not past`
(:115-117), hop `expires_at` monotonic-narrowing (:280,:300-301,:329-330),
replay nonce outlives lease (:222). Claim-time: **none** — confirmed gap.
C4 plan: capture `authority_expires_at = min(lease.Expiry, terminal-hop
ExpiresAt)` on the `Continuation` at `handleCreate` (server-side, same
point LeaseID etc. are bound); `CheckClaimAuthority` gains an additive
first check: `now.After(authorityExpiresAt) → deny`. No interface change —
field is additive on the record, checker signature unchanged in shape
(pass store clock or `time.Now` — deterministic via injectable `now`).

---

## 13. INTERFACES THAT MUST NOT CHANGE

- `ClaimForExecution(id, executor) (*Continuation, bool)` signature + atomicity
- `CheckClaimAuthority(rc, c) (deny, reason, err)` shape — additive field checks inside
- `bindIdentity` principal overwrite; delegation evaluator semantics
- `CanonicalResource`; `OnceConsume` replay semantics; PoP semantics
- `gwidentity` key lifecycle + `ResolveVerifyKey` contract
- `edsig_v1` receipt payload format; proxy custody/SSRF/scrubbing
- approval authority derivation (`resolvedBy` = authenticated principal)
- `Store` interfaces (`continuation.Store`, `approval.Store`, …) — callers unchanged
- `reconcileAnchor` frozen table; existing fail-closed config guards

All store conversions happen INSIDE the store implementations (file layer),
so handlers/evaluator never see the journal machinery.

---

## 14. PROPOSED ADDITIVE CHANGES (implementation order per §19)

1. `internal/record` (NEW package): `Envelope`, `Signer`, `Verifier`,
   `Fold` engine — canonical lp-framing (reuses `internal/identity/canon.go`
   conventions), ed25519 sig, `key_ref` resolution via gwidentity,
   positional `parent = sha256(prev physical line)`, `seq` monotone,
   transition-table fold with total legality, tombstone handling.
2. `docs/OVARA_2.1_JOURNAL_SPEC.md` (this plan's §companion) — formal spec.
3. C5/C6: journal envelope + fold engine (item 1).
4. Convert stores to signed journals, claim-path first: `continuation` →
   `approval` → `execution` → `replay`/`revocation` line-signing →
   `idregistry` signed-snapshot envelope → `capabilities` → new
   `decision` journal.
5. C1: `TipsRecord` kind + ledger writer + open-time tip verification
   (strict when a checkpoint exists; per-store policy when none —
   bootstrap rule defined in decisions doc).
6. C3: unconditional identity gate at both dispatch sites.
7. C4: `authority_expires_at` capture + claim check.
8. Migration: `internal/migrate` + `gwctl migrate`.
9. Compaction: tombstone retention + signed `compact` events.
10. Adversarial test suite (TAIL/FOLD/IDENT/LEASE/STORE/MIG/COMPACT).
11. Regression: all frozen suites + `-race` + proxy + clean-room.

## 15. SECURITY PROPERTIES AFFECTED

ADDED: journal authenticity (all authority stores), positional-chain
integrity (no reorder/insert/delete/fork), transition totality (no
resurrection/implicit transitions), truncation detection via tip-ledger
(anchored), unconditional executor identity binding, claim-time expiry
deny, migration provenance, compaction tombstones.

UNCHANGED: claim linearization point, evaluator gate order, revocation
semantics, receipt signing, proxy boundary, all P2.3 residual limitations
(hardware root, clone-proofing, global replay, execution truth, kernel
containment) — out of scope per §1.

NOT CLAIMED: config/policy bootstrap tamper resistance (C2 deferred ���
documented trust root), whole-domain atomic rollback atomicity (oracle
limitation), execution truth.

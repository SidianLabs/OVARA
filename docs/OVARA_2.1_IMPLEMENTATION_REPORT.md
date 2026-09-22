# OVARA 2.1 — Implementation Report

Date: 2026-09-22
Branch: `devin/1790095116-ovara-21-cbda` (on top of `fb1debc` = main@000d70b + PR #5 macOS anchor fix)
Scope: adversarial-review conditions C1, C3, C4, C5, C6. C2 deferred (not approved). `policy_epoch` not implemented by instruction.

## STATUS

**OVARA 2.1 IMPLEMENTATION STATUS = READY FOR ADVERSARIAL SECURITY GATE**

Every condition C1–C6 that was in scope is PROVEN by test. No production interface named in the do-not-touch list changed shape; all new surface is additive (variadic `*record.Binding` trailing params, new fields, new files).

## Files changed / added

New package `internal/record` — the signed-journal core:
- `internal/record/record.go` — `Envelope` (v, type, domain_id, seq, record_id, parent, links, payload, key_ref, sig), `Journal` (Open/Append/Absorb/ResumeAt/Tip/Close), `Signer`, `Binding`, `Floor`, `TipHash`, `GenesisParent`, record types `migration`/`tombstone`/`compact`. LP-framed signing payload; ed25519 via `ResolveFunc`.
- `internal/record/sealed.go` — `SealedFile`/`FileSec`, `SealFile`, `OpenSealedFile` for atomic-rewrite stores (idregistry, capabilities). Payload is compacted before hashing so `data` round-trips byte-identically.
- `internal/record/record_test.go` — round-trip, fold rejections (reorder, dup, delete-middle, parent mismatch, payload tamper, seq gap), domain transplant, floor truncation (met/below/deleted), torn-tail tolerance, sealed-file verification.

Per-store conversion (all variadic-bound; nil binding = byte-identical legacy path):
- `internal/continuation/{fold,file_store}.go` — full transition table (C5), tombstone + compact fold, signed journal, `SetTipsSink`/`JournalTip`.
- `internal/approval/{fold,file_store}.go` — pending→{approved,denied} table, approved→approved resume-once, genesis-over-tombstone refusal, Delete→tombstone, tombstoned-id Create refusal.
- `internal/execution/{fold,file_store}.go` — pending/running genesis, terminal genesis only under `compacted_through` marker, terminal resurrection refusal, compact `removed_ids`.
- `internal/replay/store.go` — signed consume journal; multi-process `flock`+`Absorb` preserved; compaction disabled in signed mode (a rename would fork sibling chains — documented ceiling).
- `internal/receipts/{fold,file_store}.go` — decision journal; receipt fold (dup receipt_id fails), compact eviction envelopes.
- `internal/events/{fold,file_store}.go` — evidence journal; sticky `journalErr`+`LastError()` because Append is void.
- `internal/idregistry/registry.go`, `internal/capabilities/file_store.go` — sealed-file mode: `_sec`+`data` snapshot chained via `file_seq`/`prev_file_sha256`, tips sink after each durable write.
- `internal/enrollment/service.go` — **deliberately unchanged** (reverted): the enrollment file is read before `initGatewayTrust` runs, so no signer exists at read time; sealing it would silently re-mint `gw_id` per restart. It is a bootstrap input in the same class as `config.json` — its integrity is the deferred C2 boot-attestation story. This is a recorded decision, not an oversight.

New supporting code:
- `internal/gwidentity/store.go` — `Tip{Seq,Hash}`, `TipsRecord`, `RecordTips(gatewayID,tips)` (chained+fsynced+auto-anchored), `LatestTips`, `FindByPub`, `Migrated`.
- `internal/continuation/store.go` — `AuthorityExpiresAt *time.Time` + `WithAuthorityExpiry`.
- `internal/continuation/revocation.go` — C4: unconditional expiry check at top of `CheckClaimAuthority`, before the `rc == nil` fast path.
- `internal/continuation/orchestrator.go:192`, `internal/handlers/continuations.go:548` — C3: `o.identityChecker != nil && !o.identityChecker(cnt.AgentID)` — the gate fires whenever a checker exists, including for `agent_id == ""` (fails closed).
- `internal/handlers/approval.go` — `authorityExpiry`/`minInto`: `min(lease.Expiry, every non-zero hop ExpiresAt)` captured on the continuation.
- `internal/config/config.go` — `journal_signing_required` flag: when set and durable signing is impossible, the server refuses to start rather than silently running unsigned.
- `pkg/server/server.go` — binding block: `durableSigning` requires both `gateway_registry_file` AND `gateway_key_file` (an ephemeral key cannot verify across restart); `bind`/`sinkFor`/`postOpenRatchet` wire all eight stores and ratchet the ledger floor on open (store ahead → floor advances; store behind/missing → refuse).
- `proxy/cmd/ovara/main.go` — `ovara init` now writes `var/gateway.key` + durable `*_file` paths + `journal_signing_required: true`; `-force` preserves an existing key. Fresh deployments are durable-signed by default.
- `cmd/gwctl/main.go` — `gwctl migrate`: per-store plan, quarantine to `*.pre21`, sealed verbatim import (idregistry/capabilities), verified import (receipts via `receipt.VerifySignature`, replay live-keys only), quarantine-only for mutable-state stores (continuation/approval/execution/events), `TypeMigration` provenance marker, `RecordTips` ledger commit, idempotent re-run via `alreadySigned` sniffing.

## Adversarial test coverage (new tests, all passing)

`internal/continuation/adversarial_21_test.go` (12): FOLD-01 terminal resurrection refused; FOLD-02 executed→resumed iff `LastExecutionSucceeded==false`; FOLD-03 terminal restatement legal / outcome flip refused; FOLD-04 terminal genesis refused ×4 states; FOLD-05 unknown state+record type refuse; FOLD-06 core-field mutation mid-chain refused; STORE-01 unsigned legacy file fails closed; STORE-02 foreign-domain journal refused; TAIL-01 truncating the denied tail is refused by the ledger floor (prefix folds to `queued` without the floor — demonstrating exactly why the floor exists); LEASE-01/02/03 expiry-deny/live-pass/nil-legacy; IDENT unconditional gate — `agent_id==""` and dead identities never reach `executing` while a live identity executes.
`internal/approval/adversarial_21_test.go` (2): unsigned file refuse; fold table (flip refuse, genesis-over-tombstone refuse, restatement ok, approved genesis refuse).
`internal/execution/adversarial_21_test.go` (2): unsigned refuse; terminal resurrection / bare terminal genesis refuse, compact-remnant terminal genesis legal.
`internal/replay/adversarial_21_test.go` (2): unsigned refuse + signed claim/replay/reopen; truncate-below-floor refuse.
`internal/events`, `internal/receipts`, `internal/idregistry`, `internal/capabilities` adversarial files: unsigned refuse, sealed/journal round-trip, foreign-domain refuse, floor-ahead refuse.
`cmd/gwctl/migrate_test.go` (3): MIG-01 idempotent re-run, MIG-02 honest replay import (live kept, expired+corrupt dropped, enforced on reopen), MIG-03 quarantine-collision refusal (subprocess, since `fatal` exits).
`internal/record/record_test.go`: FOLD/TAIL rejection classes at the envelope layer.

Counts: **35/35 gateway packages pass**, `go test -race ./...` clean, proxy 6/6. 25+ new adversarial test functions.

## Security properties now enforced

- Every authority-bearing store record is gateway-signed, domain-bound, sequence-chained, and parent-hashed to the previous **physical** journal line (C6): `parent = sha256(previous line bytes)`, verified at fold; mismatch → open fails.
- Total (state,event) tables at fold for continuation/approval/execution — no ignored transitions; terminal states `{denied,expired,executed,cancelled}` non-resurrectable (C5).
- Tip-ledger committed floor (C1): tips are recorded in the already-anchored gwidentity chain strictly after the covered mutation's fsync; a store ahead of the ledger ratchets the floor at open; behind/missing → refuse. Tail truncation no longer silently resurrects queued work.
- Executor identity gate unconditional wherever a checker is configured (C3); empty `agent_id` fails closed.
- Claim-time check covers captured authority expiry (C4) — a lease/authority that expired between evaluation and claim is denied at `CheckClaimAuthority`, before the revocation fast path.
- `journal_signing_required` makes "unsigned durable state" a config-visible, refusable condition instead of a silent default.

## APIs unchanged / new

Unchanged (do-not-touch honored): `ClaimForExecution` interface, `CheckClaimAuthority` signature (added check is internal, pre-rc), `bindIdentity` principal overwrite, delegation evaluator semantics, `CanonicalResource`, replay `Consume` contract, gateway PoP, identity lifecycle, `edsig_v1` receipts, proxy custody/SSRF/scrubbing, approval authority derivation, all existing fail-closed guards.
New (additive only): `record` package API; `Store` constructors' variadic `bindings ...*record.Binding`; `SetTipsSink`/`JournalTip` on bound stores; `gwidentity.Registry.{RecordTips,LatestTips,FindByPub}`; `Continuation.AuthorityExpiresAt`+`WithAuthorityExpiry`; `Registry.Open(path, bindings...)`; `FileBackedStore` variadic params; `Orchestrator.SetIdentityChecker`/`ContinuationHandler.SetIdentityChecker`; `config.JournalSigningRequired`; `gwctl migrate`.

## Crash / rollback behavior

- Torn final line tolerable only as an uncommitted partial write (verified: `TestTornTail`).
- Crash between store-write and tip-commit: store ahead → ratchet at next open, no loss.
- Rolled-back/deleted file: floor refuses the open.
- Signed-mode journal append failure in events is sticky (`LastError`) — evidence writes never silently degrade.

## Perf / storage impact

- Journals: +1 signed line per mutation vs. legacy whole-file rewrite — writes become O(1) append instead of O(n) rewrite for sealed stores; roughly equal for prior jsonl stores, plus signature verify cost at open only.
- Sealed stores: one signed snapshot per persist (same I/O as before + signature).
- Tip-ledger: one gwidentity record per store flush batch (sinks aggregate per call, not per record).
- Compaction unchanged for legacy mode; signed mode compacts via `ResumeAt` marker-rewrite (continuation/execution) or is disabled where multi-process sharing exists (replay — documented ceiling).

## Claims changed vs. the 2.1 design doc

- Enrollment file deliberately **unsealed** (bootstrap input; C2 boundary) — D-docs updated accordingly.
- Terminal same-state rewrites are LEGAL (real race: `MarkRequeue`+`Update` on an unchanged terminal record); executed-outcome flips still refused.
- Execution compaction uses a `compacted_through` marker rather than continuation tombstones — records are deleted outright.
- `agent_id` is gated unconditionally, not only when non-empty (frozen-surface change in the deny direction only, per approved C3).

## Claims NOT made

- No claim that unsigned in-flight 2.0 continuations can be verified — they quarantine, they do not import.
- No claim that file-level ACLs / deployment boundaries were removed — a writer who can hold the signing key or pre-fork the domain still owns the trust domain; C2 boot attestation is the open mitigation.
- No claim of multi-writer safety on journals other than replay (`flock`+`Absorb`); the other stores assume the single gateway process, same as before.
- No performance benchmarks were run; the perf section above is analytical.

## Per-condition verdicts

- **C1 tip-ledger** — PROVEN. Ledger inside gwidentity (chained, fsynced, anchored); floor enforcement + ratchet + refuse paths tested (`TestAdv21_TAIL01`, replay truncate test, sealed floor tests, record floor tests).
- **C2 boot attestation** — DEFERRED (not approved). `journal_signing_required` ships the fail-closed half; remote-attestation/binding of config remains open.
- **C3 unconditional identity gate** — PROVEN. Both dispatch sites gate on `checker != nil && !checker(agentID)`; adversarial test shows `""`/dead identities never execute, live does.
- **C4 lease-expiry at claim** — PROVEN. `AuthorityExpiresAt = min(lease, hops)` captured at approval; unconditional check in `CheckClaimAuthority`; LEASE tests green.
- **C5 total transition table + tombstones** — PROVEN. Per-store fold tables refuse unknown/illegal/terminal-genesis/resurrection; tombstone retention tested incl. post-compact.
- **C6 positional parent** — PROVEN. `parent = sha256(previous physical line)` enforced in `record.Open` fold; reorder/dup/parent-mismatch/payload tamper all refuse.

End of report.

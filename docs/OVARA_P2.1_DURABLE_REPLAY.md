# OVARA 2.0 — P2.1 Durable Replay Protection

Status: implemented. Closes I11 within the defined trusted state
domain. RC1 remains the frozen regression baseline; all RC1 semantics
(canonicalization, signed nonces, issuer verification, subject binding,
audience, capability scope, policy/lease/approval enforcement,
identity binding, proxy behavior) are unchanged — P2.1 changes only
the durability of replay state.

## 1. Security property

> For a valid capability presentation, identified by
> `presentation_id`, a durable consume produces at most ONE
> `FIRST_CONSUME` within the record's lifetime across the trusted
> gateway state domain — restarts, crashes, and concurrent
> presentation notwithstanding. Every subsequent presentation of the
> same id within the lifetime returns `ALREADY_CONSUMED` and the
> evaluation denies.

**Trusted gateway state domain** (implementation definition):
the set of gateway processes sharing one replay journal file on a
single filesystem — the scope of `flock(LOCK_EX)`. Two gateways on
different filesystems are different domains; there is no cross-host
replication in P2.1 (D-04 remains open for clustered deployments).

- **Identity of a presentation**: delegation = unchanged
  `sha256(lp(issuer)‖lp(terminal_nonce))` (canonical length-prefixed
  tuple, collision-free); request = client nonce. Namespaced by kind
  (`deleg`/`req`) — a request nonce can never poison a delegation key.
- **Lifetime**: delegation records live until the chain's effective
  expiry (tightest hop `expires_at`; unbounded chain = permanent
  record). Request-nonce records live 5 minutes (RC1 semantics).
- **Atomicity**: check+insert are one operation under `flock` +
  in-process mutex — never check-then-write.
- **Persistence**: append-only JSONL journal; a consume returns
  `FIRST_CONSUME` only after `fsync`.
- **Replication assumptions**: shared filesystem only; no cross-host.
- **Failure semantics**: `STORAGE_FAILURE` → deny (fail closed).
- **Recovery semantics**: see §7.

## 2. Threat model

| Threat | Control |
|---|---|
| Replay after restart | Durable journal reload |
| Replay after crash (kill -9) | fsync before FIRST_CONSUME |
| Concurrent duplicate (1 process) | mutex + atomic consume |
| Concurrent duplicate (N processes, same fs) | flock + tail-read |
| Forged/mutated artifact poisons replay | mark only after full crypto validation (unchanged) |
| Request nonce poisons delegation key | kind namespacing |
| Replay-state unavailable → silent allow | STORAGE_FAILURE → deny |
| Corrupt journal | mid-file corruption → open fails; torn tail → truncated |
| Journal growth | expiry + compaction under flock |
| Backup restore resurrects consumed id | **documented limitation — §13** |
| Journal deleted/replaced | **documented limitation — §13** |
| Two gateways, different filesystems | out of domain — documented |

## 3. State model

Record (one JSONL line):

```
{k: "deleg"|"req", p: <presentation_id>, c: <consumed_at>, e: <expires_at?>}
```

- `p` — the replay identifier (hash for delegations; raw nonce for
  requests — client-chosen, already logged everywhere).
- `e` — absent/zero = permanent (unbounded capability).
- No secrets, no signed material, no request bodies.

In-memory: `seen` map rebuilt from the journal at open + maintained by
tail-reads. The file is authoritative; memory is a cache of it.

## 4. Storage model

Why not the existing `capabilities.FileBackedStore`: it persists by
whole-file JSON snapshot — O(n) rewrite per mutation — and has no
append semantics or cross-process tail-read. Replay needs
append+fsync per consume and shared-file coordination; the whole-file
store provides neither economically. `persist.WriteFileAtomic` is
still used for compaction rewrites elsewhere; the journal itself is
`O_APPEND`+fsync because consume durability must not depend on a
rename completing.

Layout: `replay_file` (default unset) — one append-only journal.
`replay_max_bytes` (default 8 MiB) triggers compaction.

## 5. Atomic consume semantics

```
Consume(kind, id, expiresAt):
  fast path (mutex):   seen[id] live → ALREADY_CONSUMED   (memory only)
  slow path (mutex + flock LOCK_EX):
      absorb() — read journal bytes appended since last offset
      seen[id] live → ALREADY_CONSUMED
      expiresAt past → FIRST_CONSUME (no record; capability
                       already dead — upstream denies anyway)
      append record → fsync → seen[id] → FIRST_CONSUME
  any I/O error → STORAGE_FAILURE
```

Guarantees:
- Two concurrent consumes of one live id → exactly one FIRST_CONSUME
  (tested: 64 goroutines one store; 32 across two stores/one file).
- FIRST_CONSUME ⇒ fsync completed ⇒ crash cannot lose it.
- flock serializes processes on the same filesystem — check+insert is
  atomic domain-wide.

The consume mark is still taken only after the chain's full
cryptographic validation (signature, linkage, non-amplification,
expiry, audience, subject) — a forged presentation can neither
authorize nor poison a victim's replay id (unchanged RC1 ordering).

## 6. Failure semantics

| Failure | Behavior |
|---|---|
| Journal unopenable at startup (configured) | Gateway refuses to start — never silently in-memory |
| Write/fsync/flock error at consume | STORAGE_FAILURE → request denied |
| Mid-file journal corruption | OpenFile error → gateway refuses to start |
| Torn tail (crash mid-write) | Truncated to last good record — a partial record was never a confirmed consume |
| Journal shrink detected | Another process compacted → reset+reload (lossless) |
| `replay_file` unset | Process-local 5-min caches — RC1 semantics, operator-visible log line |

No automatic fallback to in-memory when durable is configured — that
would be a silent security downgrade.

## 7. Restart semantics

- Clean shutdown: records persist; reopen → replays deny.
- Abrupt kill: every confirmed consume was fsynced before
  authorization committed → survives.
- Reopen: journal absorbed under flock; live records re-arm.
- Torn final line: truncated at open (see §6) — safe because
  fsync-before-FIRST_CONSUME means a partial write was never
  confirmed, so nothing granted is lost.

## 8. Multi-instance semantics

Implemented and tested: N gateway processes sharing one journal file
on one filesystem form one trusted state domain — flock + tail-read
makes a consume by process A visible to process B before B decides
FIRST_CONSUME. Concurrent same-id presentation across processes:
exactly one FIRST_CONSUME (tested).

NOT implemented (explicitly): gateways on different hosts/filesystems
are separate domains — a capability valid at two domain-disjoint
gateways could be consumed once each. Cross-host domains require a
shared linearizable store or single-authority model (D-04, deferred).

## 9. Cleanup semantics

- Records expire with the capability; expired records are ignored at
  lookup and dropped at compaction.
- Compaction: triggered when the journal exceeds `replay_max_bytes`;
  rewrites live records under flock on a separate non-append fd
  (truncate-in-place keeps the inode — other processes' fds stay
  valid; they detect shrink and reload).
- Correctness never depends on cleanup timing: expired records are
  harmless to keep; a re-presentation of an expired capability is
  denied upstream before consume is reached.

## 10. Migration semantics

RC1 in-memory → P2.1 durable:

- Set `replay_file`; restart. Window: in-flight consumes from the
  pre-restart process-local cache (≤5 min old) are not carried into
  the journal — a delegation replayed across that exact restart
  boundary could be consumed once more. This is identical to the
  RC1 restart behavior being fixed; the window is bounded by the
  RC1 5-minute replay cache TTL and is a one-time migration event.
  For deployments where that window matters: drain for 5 minutes
  before restart, or mint fresh nonces at cutover.
- Unsetting `replay_file` returns to RC1 semantics (with the
  operator-visible log line) — no silent downgrade: the operator
  made the choice explicitly.
- RC1 46/46 e2e passes unchanged in both modes.

## 11. Test matrix

| # | Case | Expected | Actual | Consequence |
|---|---|---|---|---|
| A | first presentation | allow | allow | consume works |
| B | exact replay | deny | deny | |
| C | replay after clean restart | deny | deny | persistence |
| D | replay after kill -9 | deny | deny | fsync ordering |
| E | 64 goroutines, same id | 1 FIRST, 63 DUP | 1/63/0 | in-process atomicity |
| F | 32 goroutines, 2 stores, 1 file | 1 FIRST | 1 | cross-process atomicity |
| G | mutated nonce | deny (crypto) | covered by existing DELEG tests | signature covers nonce |
| H | forged signature | deny | existing tests | mark never reached |
| I | wrong audience | deny | existing tests | mark never reached |
| J | wrong subject | deny | existing tests | mark never reached |
| K | expired capability | deny upstream; consume writes nothing | verified | no replay needed |
| L | store closed/dead | STORAGE_FAILURE → deny | verified | fail closed |
| M | corrupt mid-journal | open fails | verified | fail closed |
| M' | torn tail | truncated, store opens | verified | safe recovery |
| N | expired record GC | compacted away; live records kept | verified | bounded growth |
| O | duplicate batch request | deny | deny (e2e) | shared domain |
| P | single vs batch endpoint | same consume domain | verified (e2e) | choke point |
| Q | all delegation-capable endpoints | shared evaluator | verified — both funnel Evaluate | choke point |
| R | different issuer, same nonce | distinct id → allow | verified (e2e) | issuer scoping |
| S | same issuer, different nonce | distinct id | verified | |
| T | canonicalization collision | existing canon tests | unchanged | lp tuple |

E2E (tests/e2e/p21_harness.py, fresh clean-room): 7/7 —
first-allow, in-run replay deny, 8-way concurrent → 1 allow,
batch replay deny, SIGKILL-restart deny (delegation AND request
nonce), issuer-scoped nonce identity.

## 12. Performance

Measured (linux/arm64, `go test -bench`, 500 iterations):

- durable consume: ~2.2 ms — one O_APPEND write + fsync (the price
  of pre-authorization durability; bounded by disk, not contention)
- replay check (AlreadyConsumed fast path): ~183 ns — memory only
- No batching/group-commit of fsync: that would re-open the crash
  window the design exists to close.

## 13. Known limitations

- **Rollback/restore**: restoring a pre-consume backup of the journal
  resurrects consumed ids → replay possible within the capability
  lifetime. Detection requires an external high-watermark — deferred
  to receipt anchoring (P2 anchoring milestone), exactly as the P2
  design specified.
- **Journal deletion/replacement**: deleting the file is equivalent
  to a full rollback — undetectable locally. Mitigations: filesystem
  permissions (operator responsibility) + anchoring (deferred).
- **Cross-host gateways**: separate domains (§8) — a capability
  valid at two gateways on different filesystems can be consumed
  once per domain. Audience binding already prevents cross-gateway
  replay when audiences are set; empty-audience (issuer-chosen
  portable) chains are exposed to this. D-04.
- **Unbounded chains**: a delegation with no hop expiry creates a
  permanent replay record — correct but unbounded growth per
  perpetual capability (bounded by compaction of everything else).
- **fsync latency**: ~2 ms per authorization consume is the
  durability floor.

## 14. Security claims

| Claim | Classification |
|---|---|
| At-most-once consume within lifetime, single process | VERIFIED IN TEST ENVIRONMENT |
| Survives clean restart and kill -9 | VERIFIED IN TEST ENVIRONMENT |
| Atomic across processes sharing one journal | VERIFIED IN TEST ENVIRONMENT |
| Storage failure → deny (fail closed) | VERIFIED IN TEST ENVIRONMENT |
| Corrupt mid-journal → startup refusal | VERIFIED IN TEST ENVIRONMENT |
| Shared consume across check/batch endpoints | VERIFIED IN TEST ENVIRONMENT |
| Rollback/restore detection | DEFERRED (anchoring milestone) |
| Cross-host multi-gateway replay consistency | ARCHITECTURAL LIMITATION (D-04) |

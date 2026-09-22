# OVARA 2.1 — JOURNAL SPECIFICATION

Normative specification for the signed, domain-bound, hash-chained journal
layer ("CBDA records") applied to every authority-bearing store. Companion
to `OVARA_2.1_IMPLEMENTATION_PLAN.md` and `OVARA_2.1_SECURITY_DECISIONS.md`.

Status terms: MUST/MUST NOT are binding; SHOULD is recommended.

## 1. RECORD ENVELOPE

Every physical journal line in an append-mode store is one JSON object:

```json
{
  "v": 1,
  "type": "<store record type>",
  "domain_id": "<hex sha256>",
  "seq": <u64, 1-based>,
  "record_id": "<domain-level record identity>",
  "parent": "<hex sha256 of previous PHYSICAL line bytes>",
  "links": [ { "kind": "<link type>", "hash": "<hex sha256>" } ],
  "payload": <store-specific record object>,
  "key_ref": { "gateway_id": "...", "key_id": "..." },
  "sig": "<hex ed25519>"
}
```

- `v` — envelope version. MUST be 1. Unknown versions fail the fold.
- `type` — names the payload schema and the transition table.
- `domain_id` — binds the journal to one gateway identity domain:
  `domain_id = sha256("OVARA-ANCHOR-DOMAIN-V1" || gwidentity_first_line)`
  (the existing gwidentity derivation — reused verbatim).
- `seq` — physical position, 1-based, MUST increment by exactly 1.
- `parent` — `sha256(previous line's raw bytes as written, including the
  trailing newline? NO — raw record bytes WITHOUT the newline)`. Genesis:
  `parent = sha256("OVARA-JOURNAL-GENESIS-V1" || domain_id || store_name)`.
- `links` — cross-record hash references (e.g. decision → request_hash,
  migration → old_file_sha256). Additive, non-authoritative evidence.
- `payload` — the existing store record JSON, byte-preserved.
- `key_ref` — `{gateway_id, key_id}` resolved via gwidentity
  `ResolveVerifyKey` (historical keys remain verifiable).
- `sig` — `ed25519.sign("OVARA-RECORD-" + type + "-V1" || lp(domain_id) ||
  lp(record_id) || u64be(seq) || lp(parent) || lp(payload) || lp(key_ref))`
  using the same length-prefixed framing convention as `identity/canon.go`
  (`lp` = u32be length prefix; `u64be` = 8-byte big-endian).

The signature covers seq and parent, so reordering, insertion, deletion,
duplication, and forking all invalidate signatures AND fail the positional
check — belt and suspenders, each catches what a buggy check of the other
would miss.

## 2. WRITER

`record.Writer` owns one open append file:

1. compute `parent` from the previous physical line bytes
2. marshal envelope in FIXED field order (canonical JSON — no map iteration)
3. `line = json.Marshal(envelope) + "\n"`; write + fsync
4. return `(seq, lineHash)`

`record.Writer` MUST be the only append path; stores never `os.WriteFile`
directly once journalized.

## 3. FOLD

`record.Fold(file, resolver, transitions) (state, tipSeq, tipHash, error)`:

for each physical line:
1. `json.Unmarshal` → malformed JSON = FOLD ERROR
   (exception: a torn FINAL line is an uncommitted partial write iff the
   file does not end mid-line — the last line lacks `\n`; every
   mid-file anomaly is fatal)
2. `env.V == 1` else FOLD ERROR
3. `env.Seq == prev+1` else FOLD ERROR
4. `env.Parent == sha256(prevLineBytes)` else FOLD ERROR
5. `env.DomainID == expected` else FOLD ERROR (transplant)
6. verify `env.Sig` via `resolver.ResolveVerifyKey(env.KeyRef)` else
   FOLD ERROR (unknown key = fold error, not skip)
7. `transitions.Apply(foldedState, env)` — store-specific legality:
   - unknown `record_id` → genesis rules
   - known `record_id` → transition must be LEGAL and immutable fields
     MUST be byte-equal
   - unknown `type` → FOLD ERROR (no "ignored events")

Returns `(foldedState, seq_of_last_line, sha256(last_line_bytes))` — the
store tip. A fold error on a security-critical store MUST abort `Open`
(fail closed; no skip/repair/reconstruct).

## 4. TRANSITION TOTALITY (C5) — CONTINUATION TABLE

States: `escalated approved queued executing denied resumed expired
executed cancelled`. Terminal = `{denied, expired, executed, cancelled}`.

The table encodes exactly the guards in `store.go` — fold legality equals
runtime legality (nothing the runtime can write is rejected):

| from → to | legal iff |
|-----------|-----------|
| genesis → non-terminal | always |
| genesis → terminal | NEVER |
| any → same | ¬terminal iff only mutable bookkeeping differs; `executed→executed` requires `last_execution_succeeded` identical |
| ¬terminal → approved | always (MarkApproved guard) |
| approved → queued | MarkQueued |
| executing → queued | MarkRequeue |
| ¬terminal → denied | always |
| ¬terminal → resumed | always (MarkResumed) |
| executed → resumed | iff `last_execution_succeeded == false` (Retry) |
| {executing, resumed} → executed | always |
| ¬terminal → expired | always |
| {queued, resumed} → cancelled | always |
| {approved, queued, resumed} → executing | claim boundary |
| terminal → other | NEVER (except executed→resumed rule) |
| unknown strings | NEVER |

Immutable core fields (byte-equal across all records of one id):
`continuation_id, decision_id, approval_id, agent_id, subject_id,
action_type, resource, request_hash, policy_version, lease_id,
delegation_keys, issuers, authority_expires_at, created_at`. Mutable:
`state`, `*_at` lifecycle timestamps, `resolved_by`, `deny_reason`,
`retry_count`, `last_execution_succeeded`, `metadata`, `expires_at`,
`last_claimed_at`, execution bookkeeping.

Other stores' tables are degenerate (append-only → no per-id transitions;
the fold still enforces sig/seq/parent/domain):

- `execution`, `replay`, `revocation`: genesis-per-line, no same-id reuse.
- `approval`: `pending → {approved, denied}` terminal; same-state rewrite
  legal; `approved/denied → *` never; immutable: `approval_id,
  decision_id, request_hash, policy_version, subject_id, action_type,
  resource, lease_id, created_at`.
- `gwidentity` `tips` records participate in the gwidentity chain, not a
  per-record state machine.

## 5. WHOLE-FILE SIGNED SNAPSHOTS

`idregistry`, `capabilities`, `enrollment`, `receipts`, `approval` (if it
stays whole-file) use:

```json
{ "_sec": { "v":1, "domain_id":"...", "file_seq":N,
            "prev_file_sha256":"...", "payload_sha256":"...",
            "key_ref":{...}, "sig":"..." },
  "data": <existing whole-file JSON> }
```

`file_seq` increments per rewrite; `prev_file_sha256` chains snapshots.
Open MUST verify: domain, sig, `payload_sha256`, `file_seq` regression
against the tip-ledger floor (§6). Missing/invalid `_sec` where the store
is configured durable → refuse (strict) per the mode decision.

## 6. TIP-LEDGER (C1)

- Vehicle: new gwidentity journal kind `tips`: `TipsRecord{gateway_id,
  issued_at, tips: map[store_name]{seq, tip_hash}}`. Fold keeps the latest
  per `(gateway_id, store_name)`.
- WRITES: after any authority-store mutation batch is fsynced, the ledger
  appends a tips record covering the touched stores; a ratchet at open
  covers anything newer.
- RULE (committed floor): at store open,
  `journalTip.seq >= ledgerTip.seq` AND the journal's record at
  `ledgerTip.seq` MUST hash equal to `ledgerTip.tip_hash`.
  - store AHEAD of ledger → the leading tail is authenticated by its own
    chain but not yet checkpointed → ledger ratchets it at open (writes a
    new tips record covering current tip).
  - store BEHIND ledger, or record at floor mismatches → REFUSE
    (truncated committed state — impossible honestly).
  - store file missing while ledgered → REFUSE (deleted store ≠ empty).
  - store present, no ledger coverage → unsigned legacy → migration path
    (§7); an upgraded gateway self-adopts via open-time ratchet only when
    the file is empty/genesis.
- The ledger is evidence of expected state, never permission to
  manufacture state: unverifiable signatures still fail.

## 7. MIGRATION GENESIS

First record of a converted legacy file: `type:"migration"` payload
`{store, old_file_sha256, imported_count, operator_token_id, attested_at}`.
- `idregistry`, `capabilities`, `enrollment`: importable — every imported
  record restated as a signed record linked to the migration genesis.
- `continuation`, `approval`, `execution`: NOT imported (unsigned
  provenance cannot be vouched) — `gwctl migrate` quarantines
  (`name.pre21`) and starts a fresh journal; queued work drains or
  expires.
- Second migration genesis for the same store = FOLD ERROR
  (single-genesis rule).
- Old-file hash documents provenance; it does NOT prove the old file was
  honest — migration is an operator-attestation boundary.

## 8. COMPACTION & TOMBSTONES

- Terminal facts MUST survive compaction: pruned terminal records leave a
  `tombstone` line `{type:"tombstone", record_id, final_state, parent…}`
  keeping chain continuity and terminality.
- `_cleanup` pseudo-records are replaced by signed `compact` events
  listing retained tombstone ids; unsigned `_cleanup` lines = fold error.
- Compaction writes a NEW journal file (genesis = `compact` record with
  `compacted_through_seq` + `prior_tip_sha256` link), atomic-renamed over
  the old file; the fold accepts it iff the compaction link matches the
  ledger floor.
- Tombstones prunable only when a tips record anchored past their
  retention point exists — otherwise they persist.

## 9. CORRUPTION SEMANTICS

REFUSE on: bad JSON (non-final line), wrong `v`, seq gap, parent mismatch,
domain mismatch, signature failure, unknown key, unknown type, illegal
transition, immutable-field mutation, missing ledgered file, store behind
ledger, second migration genesis, unsigned `_cleanup`.

TOLERATED: a torn final line (no trailing newline) = uncommitted partial
write — truncated, logged as `journal.tail_uncommitted`, never folded in.

## 10. CLAIM PATH (C3 + C4, minimal additive)

- Both executor dispatch sites lose the `cnt.AgentID != ""` precondition —
  the identity gate applies unconditionally to executor-bound records;
  `agent_id == ""` fails the gate (checker bound to idregistry returns
  false for unknown ids; nil checker + non-empty agent_id keeps current
  semantics — no registry = nothing to check).
- `Continuation.authority_expires_at` (additive, omitempty) = `min(
  lease.Expiry, terminal delegation-hop ExpiresAt)` captured at
  `handleCreate` when the approval record is server-built.
- `CheckClaimAuthority` gains a first check (before revocation):
  `now.After(c.AuthorityExpiresAt) → deny "authority expired"`. Deny is
  terminal per existing semantics. Callers and signature unchanged.

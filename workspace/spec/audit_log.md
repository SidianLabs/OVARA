# Spec: Audit log + decision records (v0.9)

Closes v1's evidence-integrity class: SEC-0002 (self-asserted verify
key), SEC-0003 (unsigned/co-located anchors, silent truncation),
SEC-0011 (canonicalization gaps), SEC-0021 durability. v1 kept
hash-chained signed JSONL — keep the shape, fix the anchoring.

## 1. Decision record

```
DecisionRecord := {
  record_id:    uuid
  action:       canonical Action          # action_model.md
  action_hash:  sha256(action bytes)      # what approvals bind to
  policy_id:    hash(policy compiled IR)  # decision reproducibility
  conjuncts:    {capability, policy, provenance, revocation,
                 time, quota} → bool each  # P3 auditability
  outcome:      allow | deny | escalate(approval_id)
  agent_reason: coarse class              # what the agent saw
  op_reason:    full trace                # what the operator sees
  trust_ctx:    {score, level, epoch}
  timestamp, gateway_id, gateway_key_id
  prev_hash, sig                          # chain links, see §2
}
```

Properties:
- Every field signed. `action_hash` is the binding approvals use
  (v1 SEC-0014 fix pattern, generalized).
- `agent_reason` and `op_reason` are separate fields — the
  information-channel split is structural, not presentation-layer.

## 2. Log construction

- JSONL chain, `prev_hash` links, `sig_v1:` Ed25519 over pipe-
  delimited canonical form (keep v1's format — it's sound; v1 corpus
  receipts.json verified chainable today).
- **Write-ahead (P7)**: executor waits for the record's fsync ack
  before the action runs. Crash between write and exec → the record
  exists, marked `unexecuted`, reconciled on boot.
- Refuse-to-fork preserved (v1's chain.go already aborts on
  unparseable tail — verified).

## 3. Checkpoints — the actual fix

Signed checkpoint every N records and every T seconds:

```
Checkpoint := {
  tree_size, root_hash:   Merkle root over records[0..size)
  epoch, timestamp, gateway_id
  sig:                    Ed25519 over the above
}
```

- Checkpoint sig is produced by the **checkpoint key**, different from
  per-record sig key when separation exists (both in TCB).
- Checkpoints are **pushed off-host**: operator-pinned destination —
  options: (a) operator's external store via append-only API;
  (b) a public transparency log (Sigsum-style); (c) at minimum a
  second local machine's file. The point is the attacker can't rewrite
  the anchor by compromising the gateway host (v1's co-located
  anchor file allowed exactly that — SEC-0003).
- Truncation detection: checkpoint N declares tree_size=N; a verify
  on a truncated file fails the tree_size match immediately.
  Reorder/delete detected by Merkle root mismatch.

## 4. Verification (`ovara verify`)

- Required key sources, in precedence: explicit `-pubkey` flag →
  operator-pinned key file out-of-tree → embedded domain key.
- **Silent sibling-file fallback removed entirely** (SEC-0002): if no
  trusted key resolves, verify exits nonzero. The error names what it
  refused to trust.
- Verify outputs: total, chain validity, last-checkpoint coverage,
  whether entries past the last checkpoint exist (they're
  unanchored — flagged, not silently valid).
- `verify` on an empty log = error, not `valid:true,total:0` (v1 bug).

## 5. Compression + scrub interaction (SEC-0001 fix)

Receipts record the *canonical action*, not wire bytes. Response
scrubbing now runs on decompressed content: the proxy must
decompress before the scrub path — it inspects semantic content, not
gzip bytes. [VERIFIED gap in v1 proxy.go:559-562 — resp.Body raw
bytes scrubbed; explicit Accept-Encoding defeats it.]

## 6. Retention + rotation

- Journal compaction keeps the chain verifiable: rotation creates a
  checkpoint + carries `prev_root` forward — a rotated-out prefix is
  covered by its checkpoint root even after compaction.
- Replay/dedup stores are distinct journals with own checkpoints —
  not piggybacked on the audit log.

## 7. Fail modes (P2)

- Signer unavailable → no writes → no executions (fail-closed,
  not degrade-to-plaintext).
- Checkpoint push fails → alarm + bounded queue; if queue fills,
  the executor refuses new actions (availability trade recorded in
  DECISIONS; security dominates availability by default).

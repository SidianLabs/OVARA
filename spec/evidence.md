# C4 — Evidence: the receipt chain (spec 0.1)

Every decision the proxy makes leaves a **receipt**: one line of JSON,
signed, linked to the line before it. The chain is what `ovara log`
verifies, what `ovara log export` and the incident bundle carry, and what
the Python and TypeScript verifiers check against the vectors in
`sdk/testdata/receipts_v2.json`. Schema:
[`schemas/receipt-v2.schema.json`](schemas/receipt-v2.schema.json).

(The gateway keeps its own signed journals of decisions and approvals;
they are described in `docs/api/execution_receipts.md` and are not this
contract.)

## 1. A line

A line is **exactly** the JSON encoding of the receipt with its members in
the schema's order and no others, followed by `\n`. A reader decodes
strictly: unknown members, duplicate members, members in another order, or
any spelling other than the one the encoder produces are refused. Without
this, bytes outside the signature could still verify.

Members (all strings unless said): `v` (2; absent on a legacy v1 line),
`receipt_id`, `session_id`, `timestamp` (RFC 3339, nanoseconds), `method`,
`url`, `decision` (`allow`, `deny`, `escalate`, `error`), `status`
(integer; the upstream status, 0 when nothing was sent), `approval_id`,
`phase`, `outcome`, `attempt_id`, `agent`, `rule`, `policy_hash`,
`approver`, `req_bytes`, `resp_bytes` (integers), `body_sha256`, `reasons`
(array of strings), `kid`, `prev_hash`, `signature`. Members with no value
are omitted.

## 2. Two receipts per forwarded request

Before any byte goes upstream, an **attempt** receipt (`phase: attempt`,
`outcome: sent`) is written and synced to disk. Once the upstream answered
or failed, an **outcome** receipt (`phase: outcome`, `attempt_id` naming
the attempt, `status` and `resp_bytes` filled) is written. A request that
never went upstream (denied, held and not approved, refused by a gate) has
one receipt with no phase. So a crash between the two phases is visible as
an attempt without an outcome, and no request can reach the upstream
unrecorded.

## 3. The chain

`prev_hash` is the SHA-256, hex, of the **previous line's bytes** (without
the newline); the first receipt of a chain has `prev_hash: ""`. A receipt
is written only after the previous one, so the chain is also the order.

## 4. The signature (v2)

`signature` is `sig_v2:` followed by the hex Ed25519 signature over the
**signing form**: the domain string `ovara-proxy-receipt-v2\n`, then a
sequence of length-prefixed strings (each as a 4-byte big-endian length
followed by the bytes), in this order:

```
"v" <v as decimal>        "receipt_id" <..>    "session_id" <..>
"timestamp" <Unix nanoseconds, decimal>        "method" <..>   "url" <..>
"decision" <..>           "status" <decimal>   "approval_id" <..>
"phase" <..>              "outcome" <..>       "attempt_id" <..>
"agent" <..>              "rule" <..>          "policy_hash" <..>
"approver" <..>           "req_bytes" <decimal>  "resp_bytes" <decimal>
"body_sha256" <..>        "reasons" <count as decimal> <reason>...
"kid" <..>                "prev_hash" <..>
```

Every member name and value is length-prefixed, so no value can run into
the next; an absent string member is the empty string; `reasons` is its
count followed by each reason. The signature covers `prev_hash`, which is
how a signed receipt commits to everything before it.

A **v1** line (no `v`, `sig_v1:`) is signed over a `|`-joined payload of
the first members. It is ambiguous (a `|` in a value can move between
fields) and is verified only for receipts written before v2; a v1 line that
carries any v2 member is refused.

## 5. Keys

`kid` names the signing key: the first 16 hex digits of the SHA-256 of the
Ed25519 public key. The current public key is `receipt_pubkey.hex`; the
**history**, `receipt_keys.jsonl` next to it, has one record per key:
`{kid, pub, not_before?, not_after?, revoked_at?}`. A receipt verifies only
under a key whose window holds the receipt's timestamp and that was not
revoked by then. Rotation closes the old key's window and starts a new
chain segment under the new key; revocation as of a time invalidates every
receipt that key signed after it. A retired or revoked key cannot start a
chain again.

## 6. Anchors

Every N receipts (`OVARA_ANCHOR_EVERY` in the proxy's environment) the
chain's tip, `{seq, hash, time}`, is appended to an anchor file next to the
chain (`var/anchors.jsonl`, or `OVARA_ANCHOR_FILE`) and, when
`OVARA_ANCHOR_URL` is set, pushed to that URL off the host. Verification checks that the
chain passes through every anchor. A chain that was cut short or forked
after an anchor fails verification, and the proxy refuses to resume such a
chain (`CheckBeforeResume`) rather than append to a log that is not the one
it left.

## 7. Verification

Offline, with the chain file, the key history and the anchor file:

1. every line parses strictly (§1);
2. every `prev_hash` equals the hash of the line before it, from the first;
3. every signature verifies under its `kid`, and that key's window holds
   the timestamp and was not revoked by then (§5);
4. every attempt with an outcome is paired, and an attempt without one is
   reported;
5. the anchors hold (§6).

The result says how many receipts verified, where it failed and why, and
how many legacy lines there were. `ovara log` prints it; `ovara log export`
emits only verified receipts (JSONL or OCSF); `ovara incident bundle`
packs the chain, anchors, keys and policy for a third party to verify.

## 8. Vectors and tests

`sdk/testdata/receipts_v2.json` is generated from the Go implementation
(`proxy/internal/receipts/sdk_vectors_test.go`) and consumed by
`sdk/python` and `sdk/typescript`: each vector is a line, the key, and
whether it must verify, with why. An implementation of this contract must
pass them.

`proxy/internal/receipts`: `TestV2*`, `TestTamperedSignatureFails`,
`TestTamperedURLFails`, `TestAudit_TamperMatrix`,
`TestTruncatedLogIsDetected`, `TestTruncateThenContinueIsDetected`,
`TestRotateAndRevoke`, `TestMissingKeyWithReceiptsRefused`,
`FuzzReceiptLine`, `spec_schema_test.go`; `proxy/internal/proxy`:
`TestNoUpstreamBytesWithoutReceipt`, `TestReceiptNamesEveryApprovalAskedFor`;
`proxy/cmd/ovara`: `TestRunRefusesToResumeACutLog`,
`TestLogExportRefusesTamperedChain`, `TestPrintLog_DetectsTampering`.

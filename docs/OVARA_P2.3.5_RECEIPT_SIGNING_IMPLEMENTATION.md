# OVARA 2.0 — P2.3.5 Receipt Signing Implementation

Status: READY FOR GATE
Depends on: P2.3.1 (gateway Ed25519 identity + key lifecycle),
P2.3.4 (revocation epoch → trust_epoch)

## 1. What was built

Every receipt produced by the gateway now carries an additive
Ed25519 signature over an explicit canonical payload:

```json
{
  "receipt_id": "...", "decision_id": "...", ...,
  "trust_epoch": 7,
  "gateway_id": "gw_…",
  "gateway_key_id": "gwk_…",
  "gateway_sig": "edsig_v1:<hex ed25519 signature>",
  "signature": "sig_v1:<hex hmac>"        // unchanged
}
```

The property delivered:

> A receipt can be independently verified as having been signed by
> the gateway identity/key identified in the receipt, without
> possessing the gateway's symmetric HMAC secret.

What it does NOT deliver (explicit non-claims):

- **not completeness** — a signed receipt proves its own authenticity,
  not that every receipt that should exist does exist;
- **not immutable history** — signatures do not prevent history
  rewrite; that is what anchoring (separate phase) is for;
- **not execution truth** — a signed deny/allow receipt attests the
  gateway's *decision record*, not that an external side effect
  occurred;
- **not rollback prevention** — an attacker holding the journal file
  can still rewrite it; the P2.3.3 anchor bounds this only when
  configured;
- **not current authorization** — a valid historical signature says
  nothing about whether the signing key is trusted *now*.

> A valid Ed25519 receipt signature establishes authenticity and
> integrity of the signed receipt under the corresponding gateway key.
> It does not establish completeness, immutable global history,
> execution truth, or resistance to offline journal rollback without
> an external trust anchor.

## 2. Signing key

The signer uses the gateway's existing P2.3.1 Ed25519 private key —
no second key is generated. At startup `initGatewayTrust` admits the
key into the domain registry (durable, before serving); the
`EdSigner` is wired from `gwTrust.priv` + the admitted record's
`(gateway_id, key_id)`. Because admission precedes serving, **every
signed receipt references a key binding the registry already durably
knows** — the ordering property of §26 holds by construction.

The private key never appears in receipts, API responses, logs, the
registry, the HMAC payload, or error messages — the struct holds it
internally and only emits signatures (`TestReceiptJSON_NeverCarries
PrivateKey` asserts even the public key is absent; key resolution is
registry-side only).

## 3. Canonical signed payload

`receipt.SignedPayload(r)` — `internal/receipt/edsigner.go`:

```
lp("OVARA-RECEIPT-SIG-V1")           — explicit domain + version
lp(receipt_id) lp(decision_id) lp(action_digest) lp(action_type)
lp(resource) lp(agent_id) lp(capability_lease_id) lp(decision)
lp(policy_version) lp(trust_score %f.6) lp(trust_level)
lp(anomaly_signals)                   — each item lp(code)‖lp(pattern)‖lp(severity), stored order
lp(shield_active) lp(restricted) lp(risk_count)
lp(approval_id) lp(approval_decision)
lp(trust_epoch) lp(issued_at_unixnano)
lp(gateway_id) lp(gateway_key_id) lp(hmac_signature)
```

`lp` = u32be length ‖ bytes — the same framing as identity/PoP
canonicalization; no field is ever concatenated ambiguously. Every
`models.Receipt` field is covered except `gateway_sig` itself —
including the HMAC `signature` string, so stripping or forging the
HMAC invalidates the whole signed receipt (gate finding G2).
`issued_at` is bound at nanosecond precision (gate finding G1 —
second-precision would have left sub-second tampering undetected).
Field order is fixed by the function, not the struct.

Receipt signing deliberately does NOT reuse delegation
canonicalization — its own domain string and field set.

## 4. HMAC interaction

The RC1 HMAC mechanism is untouched: `signature` still carries
`sig_v1:<hmac>` over the RFC 0003 canonical payload, and `trust_epoch`
remains outside that preimage (the P2.3.4-reviewed property is
preserved — the Ed25519 payload binds it independently). Two
independent mechanisms:

| mechanism | proves | key |
|---|---|---|
| `signature` (sig_v1) | integrity under shared secret | HMAC key |
| `gateway_sig` (edsig_v1) | authenticity+integrity, third-party | gateway Ed25519 |

Old receipts without `gateway_sig` parse and HMAC-verify as before
(omitempty everywhere); they are simply not third-party verifiable —
`ErrUnsigned`, never silently "valid".

## 5. Verification

`receipt.VerifySignature(resolver, r)` is the single authoritative
primitive:

1. require `edsig_v1:` prefix (else `ErrUnsigned`);
2. hex-decode, require `ed25519.SignatureSize` (malformed → invalid);
3. resolve `(gateway_id, gateway_key_id)` through the resolver —
   the registry is the authority; **a key inside the receipt is never
   trusted**;
4. recompute `SignedPayload` and `ed25519.Verify`.

Resolution errors (unknown gateway/key, no registry) are returned as
errors — unverifiable ≠ valid. `RegistryResolver` reads
`gwidentity.Registry.Lookup` (absorbs the journal tail under lock —
cross-process visibility) and returns the recorded public key in ANY
lifecycle state: `usable()` is intentionally not applied — that is
the live-authentication check, not the historical-verification check.

Endpoints:

- `POST /v1/receipts/verify` — operator-only (agent → 403; the route
  is not in the agent allowlist). Body = receipt JSON; returns
  `{valid, gateway_id, gateway_key_id, reason?}`.
- `gwctl verify-receipt --registry F --receipt receipt.json` — true
  third-party verification: needs only the public registry file and
  the receipt. No secret material is involved.

## 6. Rotation & revocation semantics

Rotation (startup `force_rekey`, unchanged P2.3.1 semantics):

- receipt signed by K1 → rotate to K2 (K1 superseded) → K1's
  receipts still verify — the registry keeps the historical record;
- receipts minted after rotation carry the new `key_id` — verified
  live in e2e R16.

Key revocation:

- `RevokeKey` kills live authentication (`AuthenticatePeer` denies —
  `usable()` fails);
- historical receipts signed by that key **remain cryptographically
  valid** — cryptographic truth is not rewritten by revocation.
  `TestRevokedKey_HistoricalValidLiveDenied` pins both halves.

Receipts are never rewritten when keys rotate or die — RVI-11
extends: historical evidence stays byte-identical.

## 7. trust_epoch semantics

`trust_epoch` = the domain revocation epoch (journal seq) observed at
decision time (P2.3.4). P2.3.5 binds it into the Ed25519 payload —
tampering with it invalidates the signature (R11 live, unit matrix).
It remains **same-domain context**: the epoch attests what THIS
gateway's revocation view was — not global distributed truth, and a
valid epoch-bound receipt does not imply the authority is still
active (R15: receipt stays valid after the epoch moves).

## 8. Receipt creation paths — audit

Exactly one: `recordDecision` → `buildReceipt` → `receiptsStore.Put`
(shared by `/v1/runtime/check` and `/v1/runtime/batch-check`). The
signature stamps server-side fields derived from the recorded
decision — agents cannot submit receipt material; the private key
never leaves the server. Decisions that produce receipts (allow,
policy-deny, escalate) all produce signed receipts; pre-evaluation
rejects (malformed request, replayed nonce, stale min_epoch) produce
no receipt at all — existing semantics unchanged. Without gateway
trust (open/dev mode, `gwTrust == nil`) receipts keep the HMAC-only
form — unsigned is honest; nothing claims to be a P2.3.5 receipt that
isn't.

## 9. Hash-chain interaction

Receipts carry no hash-chain fields — the receipt store is a flat
keyed journal, not chained (that property lives in the gwidentity
journal, which the KEY side of this design inherits). The signature
therefore covers the complete receipt content; there is no chain
reference to detach from.

## 10. Security invariants (RS-01..12)

| RS | invariant | status | evidence |
|----|-----------|--------|----------|
| 01 | receipts carry gateway+key identity | PROVEN | R3/R4 e2e; SignReceipt stamps before signing |
| 02 | sig by gateway Ed25519 priv | PROVEN | EdSigner over gwTrust.priv; R5/R9/R10 |
| 03 | independent verify via authoritative key | PROVEN | R10 gwctl offline verify — no secrets |
| 04 | any tampered field → invalid | PROVEN | 26-field unit matrix + 17-field e2e R11 |
| 05 | id substitution fails | PROVEN | cross-gw, key_id swap, attacker-sig tests + R12 |
| 06 | receipt-specific domain separation | PROVEN | PoP↔receipt cross-substitution tests + R12 e2e |
| 07 | historical verify across rotation | PROVEN | unit rotation test + live R16 rekey |
| 08 | historical validity ≠ current auth | PROVEN | revoked key: verify VALID + AuthenticatePeer denied |
| 09 | trust_epoch bound into signature | PROVEN | tamper trust_epoch → INVALID (unit + e2e) |
| 10 | private key never exposed | PROVEN | JSON-leak test; struct encapsulation; R8 |
| 11 | agent cannot control receipt content | PROVEN | buildReceipt derives only from server-side decision record; verify route is operator-only (R14) |
| 12 | no immutable-history claim | PROVEN | this document §1; tests assert only per-receipt authenticity |

## 11. Attack matrix (all executed)

| attack | expected | result |
|---|---|---|
| modified receipt_id / decision_id / action_digest / action_type / resource / agent_id / lease / decision / policy / trust_score / trust_level / anomalies / shield / restricted / risk / approval_id / approval_dec / trust_epoch / issued_at / gateway_id / gateway_key_id | INVALID | all INVALID (unit, 21 cases; e2e 12 cases) |
| attacker-signed claiming victim key | INVALID | INVALID (unit+e2e) |
| cross-gateway gateway_id | INVALID | resolution error (unit+e2e) |
| wrong key_id (rotated sibling) | INVALID | INVALID |
| caller-supplied pubkey | n/a — API accepts no pubkey | verify resolves registry only |
| PoP sig as receipt sig | INVALID | INVALID (unit+e2e) |
| receipt sig as PoP | INVALID | AuthenticatePeer denies |
| superseded-key receipt | VALID | VALID (unit+e2e R16) |
| revoked-key receipt | cryptographically VALID | VALID; live auth DENY |
| unregistered key_id | INVALID | resolution error |
| registry unavailable | no false trust | error, never valid |
| malformed / truncated / wrong-scheme sig | INVALID | INVALID |
| concurrent sign/verify during rotation | safe | 96-goroutine test, -race clean |
| crash → restart | durable binding | reopen registry → verify passes |

## 12. Residual limitations (unchanged architecture)

- Offline journal rollback remains possible unanchored (P2.3.4 bound).
- External/Merkle/TPM anchoring: not implemented — deferred.
- Same-domain trust boundary only; no distributed verification
  propagation.
- No kill-on-revoke for running executions (P2.3.4 semantics).
- Software key in a file — TPM/hardware backing deferred.
- Signed receipt ≠ execution truth — a valid signature attests the
  gateway's record, not external world effects.

## 13. Frozen-surface confirmation

No frozen semantics were touched: delegation/resource
canonicalization, replay keys, credential/identity lifecycle,
continuation claim linearization, revocation classes/epochs, and the
HMAC preimage are byte-identical to pre-P2.3.5. All prior suites pass
unmodified (see report). The only model change is additive fields;
the only handler change is additive signing; the only new route is
operator-scoped.

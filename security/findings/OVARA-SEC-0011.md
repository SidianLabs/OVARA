# OVARA-SEC-0011 — Evidence authenticity gaps beyond truncation: unsigned fields, ambiguous canonicalization, in-memory nonces

**Severity:** MEDIUM
**Component:** proxy/internal/receipts/chain.go, runtime/gateway receipts,
leases/delegation canonicalization
**Status:** CONFIRMED (static review + crypto reviewer)

## Evidence
- `approval_id` is rendered into the receipt text but is NOT part of the
  signed payload — it can be altered without breaking the signature.
- Unknown JSON fields on the receipt line are dropped/unsigned: an
  attacker can strip or add metadata fields while preserving `valid:true`.
- Canonicalization is pipe-joined fields — ambiguous if any field can
  contain `|`; receipt `seq` is not stored per-entry (order implied only).
- Gateway vs proxy receipts share the trust token / signing context —
  no domain separation between evidence producers.
- Lease/delegation canonicalization inconsistencies; agent identity in
  requests is self-asserted (no binding to the caller).
- Nonce cache is in-memory → replay window opens on gateway restart.

## Root cause
Receipt v1 signed a minimal field set and treated the envelope as
trusted. Anchors/seq/key-id/field-completeness were deferred to "sig_v2"
but Phase 0 shipped v1 semantics.

## Security impact
A storage-attacker (or the agent where it can touch files) can alter
unsigned context fields, replay nonces post-restart, and exploit
canonicalization ambiguity — while `ovara verify` still reports valid.
Combined with SEC-0002/0003, default evidence is self-authenticating.

## Proposed fix (P1 receipt v2)
- Sign the full normalized receipt (all fields, seq, key_id, producer
  domain tag); reject unknown fields on verify.
- Persist nonce cache (or use hash-chained receipt presence as replay
  evidence); add restart-safe replay window.
- Domain-separate signing contexts per producer.

## Regression test
Mutate each unsigned field → verify must fail; restart gateway → replayed
nonce must be rejected.

## Residual risk
None once v2 is the only accepted format.

# OVARA-SEC-0002 — verify accepts self-asserted sibling pubkey; whole-chain rewrite undetectable

**Severity:** HIGH
**Component:** proxy/cmd/ovara-proxy/main.go:77-94 (runVerify)
**Status:** CONFIRMED LIVE

## Reproduction (verified live)
1. `ovara init /tmp/evil` → fresh receipt keypair under attacker control.
2. Run proxy with `receipt.key` = evil key; mint a forged chain +
   write `receipt_pubkey.hex` next to it.
3. `ovara-proxy -verify evidence/receipts.jsonl` (no `-pubkey`)
   → `{"total":1,"valid":true}` — forged evidence verifies.

The verifier silently falls back to `<chain>.pub` then
`receipt_pubkey.hex` in the evidence's own directory. An attacker who
rewrites the chain drops their own pubkey beside it. A *mistyped*
`-pubkey` also silently falls back instead of erroring.

## Root cause
The verification root-of-trust is read from the same directory as the
evidence. Evidence is self-authenticating.

## Security impact
A host-compromise attacker (the threat model's A6-adjacent adversary)
rewrites all history and verification stays green — the chain's core
guarantee collapses unless the operator happens to supply an external
`-pubkey`.

## Proposed fix
- Require `-pubkey` (or pinned fingerprint) from outside the evidence
  directory; remove the sibling-file fallback, or at minimum print the
  key fingerprint + loud "self-asserted key" warning when used.
- Sign anchors with the receipt key; require authenticated HTTPS anchor
  sink; `verify` fetches anchors from the sink URL, not the sibling file.
- Add `seq`+`key_id` to the signed payload; verify strict increment and
  non-decreasing timestamps.

## Regression test
Forge a chain with a different key + sibling pubkey → verify must FAIL.

## Residual risk
Even with pinned keys, an attacker holding the co-located `receipt.key`
re-signs — only external anchoring bounds the damage (P1 work).

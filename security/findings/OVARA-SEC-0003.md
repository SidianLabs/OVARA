# OVARA-SEC-0003 — Tail truncation undetected; anchors unsigned/unauthenticated/co-located

**Severity:** MEDIUM (HIGH as designed, LOW value as deployed)
**Component:** proxy/internal/receipts/chain.go, anchor.go, cmd/ovara-proxy/main.go
**Status:** CONFIRMED LIVE

## Reproduction (verified live)
- Truncated the last 10 of 43 receipts → `{"total":33,"valid":true}` —
  no error, no warning. `total` just shrinks.
- Empty file → `valid:true, total:0` (per chain_test.go).
- `anchors.jsonl` lines are unsigned JSON `{seq, head, time}` — deleting
  trailing anchors alongside the truncated receipts keeps verification
  green. Anchor heads are recomputed from chain data — the local file is
  redundancy, not evidence.
- `OVARA_ANCHOR_URL` POST is unauthenticated plain HTTP, fire-and-forget,
  optional; default sink is the same `var/` dir as the evidence.

## Root cause
No `seq` in receipts; no terminator record; anchors carry no signature
and are co-located with the evidence they protect.

## Proposed fix
seq+key_id in sig_v2; signed anchors; authenticated HTTPS sink; verifier
reports "last externally-anchored seq vs file length" so truncation is
explicit; exit non-zero when no external anchor exists.

## Regression test
Truncate N lines → verify must report coverage gap and exit non-zero
when an anchor at seq>N exists; unsigned/absent anchors → loud warning.

## Residual risk
Without an off-host sink, deletion-after-last-anchor is undetectable —
inherent, must be documented honestly rather than claimed closed.

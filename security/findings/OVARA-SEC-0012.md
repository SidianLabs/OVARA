# OVARA-SEC-0012 — Non-proxied execution paths can bypass receipting entirely

**Severity:** MEDIUM
**Component:** runtime/gateway execution/check paths (batch-check,
non-HTTP action handlers) vs proxy receipt pipeline
**Status:** CONFIRMED (crypto reviewer; consistent with architecture —
receipts are emitted only inside the proxy transit path)

## Evidence
The evidence chain lives in the proxy's transit path (`recordAllowed`/
`recordDenied`). Gateway-side action evaluations that don't transit the
proxy — batch checks, direct executor calls, admin/simulate paths —
produce decisions without chained receipts. The reviewer flagged that a
caller reaching decision APIs directly gets allow/deny answers with no
corresponding evidence entries.

## Root cause
Evidence is a property of the transport, not of the decision. Two
producers, one receipt writer.

## Security impact
Actions can be authorized and executed with zero evidence — an
accountability gap, and it weakens the "every action receipted" claim.
Receipt-silence detection (P2 monitor) can't distinguish "no action"
from "action via unreceipted path".

## Proposed fix
- Emit a decision receipt at the gateway for EVERY evaluation (deny,
  allow, escalate), domain-separated from proxy transit receipts.
- Reconcile: transit receipts reference the decision event id.

## Regression test
Hit each non-transit decision path → assert a gateway decision receipt
exists and chains.

## Residual risk
Doubles receipt volume; dedupe/aggregation needed for batch APIs.

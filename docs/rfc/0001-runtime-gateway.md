# RFC 0001: Runtime Gateway

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

## Summary

Define the Ovara Runtime Gateway as the canonical decision orchestration point
for sensitive autonomous actions.

## Motivation

SDK-only enforcement is easy to adopt but too easy to bypass. A gateway creates
consistent normalization, policy evaluation, receipt issuance, and telemetry.

## Design

- receives normalized action requests
- verifies machine identity and capability leases
- evaluates policy and trust state
- emits signed decision receipts
- optionally brokers approval continuation

## Open Questions

- when should customers prefer sidecar-only mode?
- what subset of decisions can safely use cached control-plane data?


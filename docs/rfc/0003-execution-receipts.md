# RFC 0003: Execution Receipts

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

## Summary

Execution receipts are signed records proving that a sensitive action was
evaluated and executed under a specific policy and trust context.

## Goals

- portability
- tamper evidence
- post-hoc auditability
- target-side verification

## Required Fields

- receipt id
- action digest
- identity reference
- capability reference
- policy version
- decision outcome
- trust score
- signature

## Non-Goals

- storing arbitrary reasoning transcripts in the base receipt format


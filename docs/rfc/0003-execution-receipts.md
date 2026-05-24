# RFC 0003: Execution Receipts

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


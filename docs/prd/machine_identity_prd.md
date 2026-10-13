# Machine Identity PRD

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

## Problem

The industry lacks a standard, portable identity model for autonomous actors.

## Goals

- define agent identifiers
- model delegated trust relationships
- support portable verification

## Non-Goals

- full internet standardization in the first releases

## Architecture

- immutable identity root
- mutable trust metadata
- signed capability documents
- verification libraries

## UX Flows

- create machine identity
- bind to owner and runtime
- issue scoped capabilities

## API Requirements

- identity document retrieval
- signature verification
- capability resolution

## Scaling Concerns

- trust graph fan-out
- global verification latency

## Threat Models

- forged identity documents
- stale trust metadata

## Adoption Strategy

- open SDKs and reference verification libraries

## Failure Modes

- weak interoperability semantics
- ambiguous identity lifecycle state

## Rollout Strategy

- Ovara-native first, federated second


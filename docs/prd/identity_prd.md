# Identity PRD

## Problem

Autonomous agents currently inherit broad credentials rather than receiving
bounded, attributable machine identity.

## Goals

- issue machine identities to agents and sub-agents
- support delegated capability leases
- enable revocation and expiry
- sign execution provenance

## Non-Goals

- replacing corporate workforce IAM

## Architecture

- agent registry
- identity issuer
- capability lease service
- trust metadata signer

## UX Flows

- operator registers agent
- delegator issues capability lease
- agent presents identity and lease for action checks

## API Requirements

- register identity
- mint capability
- revoke capability
- verify receipt signature

## Scaling Concerns

- high-cardinality identity graph
- revocation propagation latency

## Threat Models

- impersonation
- lease theft
- unauthorized recursive delegation

## Adoption Strategy

- integrate first with Ovara Runtime-issued receipts

## Failure Modes

- stale revocation state
- broken trust-chain verification

## Rollout Strategy

- signed local identities first
- federated identity later


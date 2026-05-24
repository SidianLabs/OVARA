# Distributed Systems

## Requirements

- regional low-latency action decisions
- eventual consistency for analytics
- strong consistency for revocation and high-risk approvals

## Core Choices

- stateless runtime gateways
- replicated policy distribution
- append-only receipt log
- async analytics ingestion

## Failure Model

- gateway failure should not lose action receipts already acknowledged
- control plane partitions should degrade to locally cached policy where safe
- critical revocations need push invalidation, not polling alone


# Core Primitives

Ovara should standardize around a small set of protocol-level primitives.

## AgentIdentity

Stable identifier for a machine actor.

Required properties:

- issuer
- subject id
- owner binding
- lifecycle state
- public verification material

## CapabilityLease

Short-lived delegated authority grant.

Required properties:

- issuer
- subject
- allowed actions
- resource scope
- expiry
- delegation depth
- revocation handle

## DelegationChain

Ordered lineage of authority transfer from a root delegator to the acting
machine identity.

Required properties:

- root authority
- intermediate delegates
- chain hash
- verification status

## TrustContext

Authorization posture snapshot used at decision time.

Required properties:

- trust score
- environment classification
- anomaly summary
- attestation status
- evaluation timestamp

## ExecutionReceipt

Signed output artifact of the authorization and execution process.

Required properties:

- action digest
- decision
- policy version
- identity references
- trust context summary
- signature

## Design Rule

Any new subsystem should explain how it reads, writes, verifies, or enriches one
of these primitives. If it does not, it probably does not belong on the hot
path.


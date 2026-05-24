# Identity Architecture

## Identity Objects

- `AgentIdentity`: stable machine identifier
- `CapabilityLease`: scoped authority grant with expiry
- `DelegationChain`: ordered record of authority transfer
- `TrustMetadata`: signed attributes about runtime and posture

## Trust Boundaries

- identity issuer must be strongly authenticated
- capability minting must require an explicit delegator
- recursive delegation depth must be bounded

## Verification Model

- signature verification on all identity and capability artifacts
- revocation checks on critical paths
- binding between runtime instance and agent identity where possible


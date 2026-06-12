# Identity API

The Identity API in Ovara provides machine identity primitives: agent
registration, capability lease issuance, delegation chain management,
and trust metadata. The gateway uses ed25519 signatures and SHA-256
hash lineage for cryptographic verification.

## Core Primitives

### AgentIdentity

The stable identity of a machine actor. Each agent has a unique
`agent_id`, an ed25519 key pair, and a lifecycle state
(`active`, `suspended`, `revoked`).

```json
{
  "agent_id": "agt_001",
  "public_key": "ed25519:MCowBQYDK2VwAyEA...",
  "state": "active",
  "created_at": "2026-06-01T00:00:00Z",
  "issuer": "ovara",
  "metadata": {
    "display_name": "Production Deployer"
  }
}
```

### CapabilityLease

A short-lived, scoped delegation of authority. Leases are signed by
the issuer with ed25519 and include an expiry timestamp and delegation
depth.

```json
{
  "lease_id": "cap_abc123",
  "issuer": "ovara",
  "subject": "agt_001",
  "allowed_actions": ["shell", "exec", "git.push"],
  "resource_scope": "repo:acme/api",
  "expiry": "2026-06-01T01:00:00Z",
  "delegation_depth": 1,
  "signature": "ed25519:3045022100..."
}
```

### DelegationChain

The verifiable lineage of authority transfer. Each chain entry contains
a hash linking it to the previous entry, allowing cryptographic
verification of the delegation path.

```json
{
  "authorities": [
    {
      "issuer": "ovara",
      "subject_id": "agt_root",
      "depth": 0,
      "hash": "sha256:abc..."
    },
    {
      "issuer": "ovara",
      "subject_id": "agt_001",
      "depth": 1,
      "hash": "sha256:def..."
    }
  ],
  "chain_hash": "sha256:789...",
  "depth": 1
}
```

### TrustMetadata

Signed runtime/posture attestation. The agent's runtime publishes
trust metadata periodically to indicate its current posture (e.g., code
version, security patches applied, isolation mode).

```json
{
  "agent_id": "agt_001",
  "posture": {
    "isolation": "firecracker",
    "code_version": "1.2.3",
    "seccomp_profile": "default-strict"
  },
  "issued_at": "2026-06-01T00:00:00Z",
  "signature": "ed25519:..."
}
```

## Cryptographic Verification

The gateway evaluator cryptographically verifies:

1. **CapabilityLease signature** — the lease was signed by the claimed
   issuer and has not been tampered with.
2. **DelegationChain hash lineage** — each link's hash matches the
   previous link, preventing forged delegation paths.
3. **TrustMetadata signature** — the trust attestation was signed by
   the claimed agent.

Failed verification produces a decision of `deny` with the reason
`identity_invalid_signature` or `chain_hash_mismatch`.

## Lifecycle

```
                  ┌────────────┐
                  │  Created   │
                  └─────┬──────┘
                        │
                  ┌─────▼──────┐
                  │  Active    │◀──────┐
                  └─┬──────┬───┘       │
                    │      │           │
        ┌───────────▼┐  ┌──▼──────┐    │
        │ Suspended  │  │ Revoked │    │  Un-Revoke
        └─────┬──────┘  └─────────┘    │  (admin only)
              │                         │
              └─────────────────────────┘
                  Un-Suspend
                  (admin only)
```

## Identity Operations (Internal)

Identity management is performed by the gateway's internal
[`identity` module](../../runtime/gateway/internal/identity/) and
the standalone [`identity/`](../../identity/) module. The hosted
control plane exposes identity operations via its own API
(see [Cloud API](cloud_api.md)).

## Revocation

The gateway maintains a revocation list for issued leases. When a lease
is revoked (manually by an operator, or automatically upon agent
revocation), all decisions for that lease ID are immediately denied.

## SDK Support

The TypeScript and Python SDKs include identity verification helpers:

```typescript
import { verifyAgentIdentity, verifyCapabilityLease, verifyReceipt } from '@ovara/sdk';

const valid = verifyAgentIdentity(identity, expectedIssuer);
const leaseValid = verifyCapabilityLease(lease);
const receiptValid = verifyReceipt(receipt, signingKey);
```

```python
from ovara_sdk import verify_agent_identity, verify_capability_lease, verify_receipt

valid = verify_agent_identity(identity, expected_issuer)
lease_valid = verify_capability_lease(lease)
receipt_valid = verify_receipt(receipt, signing_key)
```

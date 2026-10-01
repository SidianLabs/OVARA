# Identity API

The Identity API in Ovara provides machine identity primitives: agent
registration, capability lease issuance, delegation chain management,
and trust metadata. The gateway uses ed25519 signatures (verified
against a configured `trusted_issuers` registry) and a SHA-256 chain
integrity hash.

## Core Primitives

### AgentIdentity

The stable identity of a machine actor, carried on each action request.

```json
{
  "issuer": "ovara",
  "subject_id": "agt_001",
  "owner": "acme-platform",
  "lifecycle": "active",
  "verify_key": "a1b2c3..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string | yes | Identity of the issuer asserting this identity |
| `subject_id` | string | yes | The agent's identifier (max 256 chars) |
| `owner` | string | no | Owning team or system |
| `lifecycle` | string | no | Lifecycle state (e.g. `active`, `suspended`, `revoked`) |
| `verify_key` | string | no | Hex-encoded ed25519 public key associated with the subject |

AgentIdentity is **self-asserted**: the gateway validates structure only
(issuer and subject_id present, length bounds). It carries no signature
and proves nothing by itself — the `CapabilityLease` is the verifiable
artifact that binds authority to the asserted subject.

### CapabilityLease

A short-lived, scoped delegation of authority. Leases are signed by
the issuer with ed25519 and include an expiry timestamp and delegation
depth. The signature is verified against the issuer's public key from
the gateway's `trusted_issuers` registry — never against a key embedded
in the lease itself.

```json
{
  "lease_id": "cap_abc123",
  "issuer": "ovara",
  "subject": "agt_001",
  "allowed_actions": ["shell", "exec", "git.push"],
  "resource_scope": "repo:acme/api",
  "expiry": "2026-06-01T01:00:00Z",
  "delegation_depth": 1,
  "issued_at": "2026-06-01T00:00:00Z",
  "revocation_handle": "rev_xyz",
  "signature": "3045022100..."
}
```

The `signature` field is the raw ed25519 signature bytes (base64 in
JSON). Unsigned leases are rejected, as are leases whose `issuer` is not
present in `trusted_issuers`.

### DelegationChain

The recorded lineage of authority transfer. A chain carries a single
keyless SHA-256 `chain_hash` over the authority entries.

```json
{
  "authorities": [
    {
      "issuer": "ovara",
      "subject_id": "agt_root",
      "delegated_at": "2026-05-31T23:00:00Z"
    },
    {
      "issuer": "ovara",
      "subject_id": "agt_001",
      "delegated_at": "2026-06-01T00:00:00Z"
    }
  ],
  "chain_hash": "789abc...",
  "depth": 1
}
```

The `chain_hash` is an **integrity check, not a proof of authority**.
Chain entries are not individually signed; the hash detects corruption
or tampering of the list as transmitted, but says nothing about whether
the delegation was authorized.

### TrustMetadata

> **Status: designed, not yet consumed.** TrustMetadata exists in the
> identity module but the V1 gateway evaluator does not read it. It does
> not affect decisions today.

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

## Verification

The gateway evaluator verifies:

1. **AgentIdentity structure** — `issuer` and `subject_id` are present
   and within length bounds. The identity itself is self-asserted; no
   signature is verified on it.
2. **CapabilityLease signature** — the lease must carry a valid ed25519
   signature that verifies against the public key registered for
   `lease.issuer` in the gateway's `trusted_issuers` config map.
   Unsigned leases and leases from unknown issuers are rejected. The
   lease's own `verify_key` field is not used as a source of trust.
3. **DelegationChain hash integrity** — the keyless SHA-256
   `chain_hash` is recomputed over the entries and compared in constant
   time. This detects corruption; it is not a signature and does not
   prove authority.
4. **Expiry, revocation, and scope** — expiry in the future, lease ID
   not on the revocation list, `action_type` in `allowed_actions`, and
   `resource` equal to `resource_scope` (or scope `*`).

Failed verification produces a `deny` decision with reason codes such
as `identity_invalid`, `capability_expired`, `capability_revoked`,
`capability_not_allowed`, or `capability_scope_mismatch`.

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
control plane exposes its own organization/gateway/policy APIs
(see `cloud/control-plane/src/routes/`).

## Revocation

The gateway maintains a revocation list for issued leases. When a lease
is revoked (manually by an operator, or automatically upon agent
revocation), all decisions for that lease ID are immediately denied.

## SDK Support

The TypeScript and Python SDKs include identity verification helpers:

```typescript
import { verifyAgentIdentity, verifyCapabilityLease, verifyReceipt } from '@ovara/sdk';

// All verify functions take the issuer's hex-encoded ed25519 public key.
const valid = verifyAgentIdentity(identity, publicKeyHex);
const leaseValid = verifyCapabilityLease(lease, publicKeyHex);
// NOTE: verifyReceipt verifies *proxy* receipts (PortableReceipt, ed25519
// "sig_v1:<hex>") — not the gateway's HMAC-SHA256 receipts.
const receiptValid = verifyReceipt(receipt, publicKeyHex);
```

```python
from ovara_sdk import verify_agent_identity, verify_capability_lease, verify_receipt

valid = verify_agent_identity(identity, issuer_public_key_hex)
lease_valid = verify_capability_lease(lease, issuer_public_key_hex)
receipt_valid = verify_receipt(receipt, public_key_hex)  # proxy receipts only
```

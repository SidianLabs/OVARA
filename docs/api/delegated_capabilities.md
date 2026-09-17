# Capability Lease API

Capability leases are the primary delegation mechanism in Ovara. A
lease grants an agent permission to perform a set of actions within a
resource scope, for a limited time, with a bounded delegation depth.

## Lease Structure

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

| Field | Type | Description |
|-------|------|-------------|
| `lease_id` | string | Unique lease identifier (`cap_*`) |
| `issuer` | string | Identity of the lease issuer; must be present in the gateway's `trusted_issuers` registry for the signature to verify |
| `subject` | string | Agent ID that holds the lease |
| `allowed_actions` | array | Action types the lease permits (`*` for all) |
| `resource_scope` | string | Resource scope the lease covers — an exact string match, or `*` for all resources (not a glob) |
| `expiry` | timestamp | When the lease expires (RFC 3339) |
| `delegation_depth` | int | Recorded delegation depth (must be non-negative) |
| `issued_at` | timestamp | When the lease was issued |
| `revocation_handle` | string | Optional handle used for revocation lookups |
| `signature` | bytes | ed25519 signature over the canonical lease payload |

## Issuance

Leases are issued by the `Issuer` service in the
[`identity`](../../identity/) module. The issuer:

1. Constructs the canonical lease payload
2. Signs the payload with the issuer's ed25519 key
3. Stores the lease in the lease store
4. Returns the signed lease to the requester

For a lease to verify at a gateway, the issuing party's public key must
be registered in that gateway's `trusted_issuers` map in `config.json`
(issuer ID → hex-encoded ed25519 public key).

## Verification

When the gateway receives an action request with a lease, the
evaluator:

1. Validates the lease structurally (required fields present,
   `allowed_actions` non-empty, `delegation_depth` non-negative)
2. Checks that the lease has not expired
3. Requires a signature; verifies the ed25519 signature over the
   canonical payload against the issuer's public key looked up from
   `trusted_issuers` — the lease's embedded `verify_key` is never used
   for trust, and unknown issuers are rejected
4. Checks that the lease ID is not on the revocation list
5. Checks that the action type is in `allowed_actions` (exact match or
   `*`)
6. Checks that the resource equals `resource_scope` exactly, unless the
   scope is `*`
7. If a delegation chain is present, recomputes the keyless SHA-256
   `chain_hash` over the entries — an integrity check that detects
   corruption but does not prove authority

If any check fails, the decision is `deny` with a specific reason code.

## Revocation

A lease can be revoked by its issuer before expiry. The gateway
maintains a revocation list. Revocations are immediate — any subsequent
request using a revoked lease is denied.

```bash
# Revoke a lease (internal API)
curl -X POST http://localhost:8080/v1/capabilities/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"lease_id": "cap_abc123", "reason": "agent_suspended"}'
```

## Delegation

> **Status: design, not implemented in the V1 gateway.** The V1
> evaluator records `delegation_depth` and validates that it is
> non-negative, but there is no `parent_lease` field and no
> subset-checking of re-delegated leases.

The intended model is that a lease with `delegation_depth > 0` can be
re-delegated: the new lease references its parent and reduces the depth
by 1, and the gateway verifies that the child's actions, resource scope,
and expiry are a subset of the parent's. This prevents a lease from
being used to mint leases with broader permissions.

## SDK Helpers

```typescript
import { verifyCapabilityLease, hasAction, isLeaseExpired, scopeCovers } from '@ovara/sdk';

verifyCapabilityLease(lease);  // verifies signature + structural validity
hasAction(lease, 'shell');     // checks if action is in allowed_actions
isLeaseExpired(lease);         // checks expiry against current time
scopeCovers(lease, 'shell:ls'); // checks if resource matches scope
```

## Storage

Leases are stored in the
[`runtime/gateway/internal/capabilities`](../../runtime/gateway/internal/capabilities/)
package. The store supports both in-memory and file-backed persistence
with retention. Leases older than the retention period are purged on
startup.

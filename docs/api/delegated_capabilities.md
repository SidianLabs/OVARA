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
  "signature": "ed25519:3045022100..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `lease_id` | string | Unique lease identifier (`cap_*`) |
| `issuer` | string | Identity of the lease issuer |
| `subject` | string | Agent ID that holds the lease |
| `allowed_actions` | array | Action types the lease permits (`*` for all) |
| `resource_scope` | string | Resource scope the lease covers (glob) |
| `expiry` | timestamp | When the lease expires (RFC 3339) |
| `delegation_depth` | int | How many times the lease can be re-delegated (0 = non-delegable) |
| `issued_at` | timestamp | When the lease was issued |
| `signature` | string | ed25519 signature over the canonical lease payload |

## Issuance

Leases are issued by the `Issuer` service in the
[`identity`](../../identity/) module. The issuer:

1. Generates a new ed25519 key pair for the lease
2. Constructs the canonical lease payload
3. Signs the payload
4. Stores the lease in the lease store
5. Returns the signed lease to the requester

## Verification

When the gateway receives an action request with a lease, the
evaluator:

1. Reconstructs the canonical payload from the lease fields
2. Verifies the signature against the issuer's public key
3. Checks that the lease has not expired
4. Checks that the action type is in `allowed_actions`
5. Checks that the resource matches `resource_scope`
6. Checks that the lease is not revoked
7. Checks the delegation chain (if any) for valid hash lineage

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

A lease with `delegation_depth > 0` can be re-delegated. The new lease
includes the original lease in its `parent_lease` field and reduces
the `delegation_depth` by 1. The gateway verifies:

1. The original lease is valid and has remaining delegation depth
2. The new lease's actions are a subset of the original's actions
3. The new lease's resource scope is a subset of the original's
4. The new lease's expiry is no later than the original's expiry

This prevents a lease from being used to mint leases with broader
permissions.

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

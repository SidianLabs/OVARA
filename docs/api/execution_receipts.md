# Execution Receipts

Execution receipts are the signed, auditable record of every
allow/deny/escalate decision and the resulting action. They are the
foundational artifact of Ovara's audit trail.

## Receipt Structure

```json
{
  "receipt_id": "rcpt_abc123",
  "decision_id": "dec_xyz789",
  "action_type": "shell",
  "action_digest": "sha256:abc123...",
  "resource": "shell:git push origin main",
  "agent_id": "agt_001",
  "capability_lease_id": "cap_def456",
  "policy_version": "v1",
  "decision": "allow",
  "trust_score": 0.85,
  "issued_at": "2026-06-01T00:00:00Z",
  "signature": "sig_v1:5f4dcc3b5aa765d61d8327deb882cf99..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | string | Unique receipt identifier (`rcpt_*`) |
| `decision_id` | string | The decision this receipt corresponds to |
| `action_type` | string | The action type that was decided |
| `action_digest` | string | SHA-256 digest of the canonical action representation |
| `resource` | string | The resource that was acted on |
| `agent_id` | string | The agent that initiated the action |
| `capability_lease_id` | string | The capability lease that authorized the action |
| `policy_version` | string | The policy version that was active when the decision was made |
| `decision` | string | The decision: `allow`, `deny`, or `escalate` |
| `trust_score` | number | The trust score at decision time (0.0-1.0) |
| `issued_at` | timestamp | When the receipt was issued (RFC 3339) |
| `signature` | string | HMAC-SHA256 signature over the canonical payload |

## Canonical Payload

The signature is computed over a pipe-delimited canonical string, not
JSON. The fields and ordering are fixed (see
[`receipt/signer.go`](../../runtime/gateway/internal/receipt/signer.go)):

```
receipt_id|decision_id|action_digest|action_type|resource|agent_id|decision|policy_version|trust_score|issued_at_unix
```

- `trust_score` is formatted as a floating-point value
- `issued_at_unix` is the Unix timestamp (integer seconds)

This canonical form is stable across releases; the field list is covered
by the signature, so modifying any of these fields invalidates the
signature.

## Signing

Receipts are signed with HMAC-SHA256 using the `receipt_signing_key`
from the gateway config:

```json
{
  "receipt_signing_key": "<32+ bytes of entropy>"
}
```

For production deployments, generate this with:
```bash
openssl rand -hex 32
```

If `receipt_signing_key` is not configured, the gateway generates a
random per-process key at startup and logs a warning. Receipts signed
under that key cannot be verified after a restart — set
`receipt_signing_key` for cross-restart verification.

The signature format is `sig_v1:<hex>` where `<hex>` is the
HMAC-SHA256 output in lowercase hexadecimal.

## Verification

To verify a receipt:

```typescript
import { verifyReceipt } from '@ovara/sdk';

const valid = verifyReceipt(receipt, signingKey);
```

```python
from ovara_sdk import verify_receipt

valid = verify_receipt(receipt, signing_key)
```

The verify functions reconstruct the canonical payload and recompute
the HMAC, then compare in constant time.

## Storage

Receipts are stored in the
[`runtime/gateway/internal/receipts`](../../runtime/gateway/internal/receipts/)
package. The store supports both in-memory and file-backed persistence.
Default retention is **60 minutes** (`receipts_max_age_minutes`, default
60; `receipts_max_size` bounds the count). For long-term archival use
the standalone [receipt-storage service](../../services/receipt-storage/),
which provides durable storage and a verification API.

## Tamper Detection

Modifying any field of a receipt invalidates its signature. There is no
gateway HTTP verify endpoint — verify with the SDK helpers above
(`verifyReceipt` / `verify_receipt`), which return `false` on mismatch,
or via the receipt-storage service's verification API.

## Cross-Org Receipts

For federated deployments, cross-org receipts use ed25519 signatures
instead of HMAC-SHA256. The cross-org receipt format includes the
issuing organization's public key and is independently verifiable
without access to the issuing gateway. See
[`trust/internal/receipt/cross_org.go`](../../trust/internal/receipt/cross_org.go)
for the implementation.

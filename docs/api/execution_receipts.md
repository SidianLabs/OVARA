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
  "policy_hash": "sha256:9b1c...",
  "gateway_key_id": "gwk_...",
  "gateway_sig": "edsig_v1:...",
  "signature": "hmac_v1:5f4dcc3b5aa765d61d8327deb882cf99..."
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
| `policy_hash` | string | Content hash of the policy that decided (`sha256:<hex>`); covered by `gateway_sig` when present |
| `gateway_sig` | string | Ed25519 signature (`edsig_v1:`) over every field, under the gateway key named by `gateway_key_id` |
| `signature` | string | HMAC-SHA256 signature over the canonical payload (`hmac_v1:`); empty when no HMAC key is set |

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

The HMAC signature format is `hmac_v1:<hex>`, where `<hex>` is the
HMAC-SHA256 output in lowercase hexadecimal. Receipts written before
October 2026 carry the old prefix `sig_v1:` for the same thing. The prefix
was renamed because the proxy's Ed25519 receipts also use `sig_v1:`.

When the gateway is used as a library with no HMAC signer at all, the
`signature` field is left empty. A placeholder signature is never stored.

The Ed25519 `gateway_sig` is the signature to rely on: anyone with the
gateway's public key can check it, and it stops verifying for receipts
dated after the key was revoked, or after a replaced key's grace period.

## Verification

- **Gateway receipts:** `POST /v1/receipts/verify` (operator token) checks
  `gateway_sig` against the gateway's identity registry. Only a valid
  Ed25519 signature is reported as valid; the HMAC is never enough.
- **Proxy receipts** (`var/receipts.jsonl`): `ovara log -verify-only`, or
  `ovara-proxy -verify`. Both use the key history next to the public key
  and the local anchors. The SDK helpers (`verifyReceipt` /
  `verify_receipt`) check v1 proxy receipts only; they do not yet read the
  v2 format described in [`SECURITY.md`](../../SECURITY.md).

## Storage

Receipts are stored in the
[`runtime/gateway/internal/receipts`](../../runtime/gateway/internal/receipts/)
package. The store supports both in-memory and file-backed persistence.
Receipts are evidence, so they are not dropped by age:
`receipts_max_size` bounds how many are kept, and the oldest go first.
(`receipts_max_age_minutes` was never applied and is no longer read; a
config that still sets it loads.) The proxy also keeps its own signed,
hash-chained receipt log (`var/receipts.jsonl`), which `ovara log`
verifies; archive that file, or use `ovara log export`, for long-term
retention.

## Tamper Detection

Modifying any field of a receipt invalidates its signatures. If the
gateway cannot store a receipt, it does not allow the action: the decision
becomes a deny with the reason `receipt_unavailable`.

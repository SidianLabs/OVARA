# Machine Identity Attacks

The machine identity system uses ed25519 signatures and SHA-256 hash
lineage to provide verifiable identity for autonomous agents. This
document describes the attack vectors specific to machine identity.

## Attack Patterns

### 1. Key Theft

An attacker steals an agent's private key.

**Defense:**
- Keys are stored in the agent's secure keystore (TPM, OS keyring,
  or encrypted file)
- Leases have short TTLs (typically 1 hour), limiting the window
  of opportunity
- The agent's `revoke` operation invalidates the key immediately
- The shield auto-restricts an agent if anomalous key usage is
  detected

### 2. Forged Identity

An attacker creates a new key pair and claims to be a trusted agent.

**Defense:**
- A self-asserted `AgentIdentity` grants nothing by itself — the
  gateway validates its structure only. What matters is the
  `CapabilityLease`
- Lease signatures only verify if `lease.issuer` is present in the
  gateway's `trusted_issuers` config map; a forged identity with a
  lease signed by an unregistered key is denied
- New issuers are enrolled through the identity issuance service, and
  their public keys must be configured into `trusted_issuers`
- The cloud control plane validates enrollment via out-of-band
  confirmation

### 3. Chain Hash Forgery

An attacker forges a delegation chain to claim authority they do
not have.

**Defense:**
- The chain carries a keyless SHA-256 `chain_hash` over the authority
  entries; the gateway recomputes it and rejects mismatches
- This detects corruption or tampering of the transmitted chain, but
  it is not a signature — chain entries are not individually signed,
  and a well-formed forged chain would pass the hash check
- Authority is therefore anchored by the signed lease verified against
  `trusted_issuers`, not by the chain; a forged chain without a valid
  trusted-issuer lease grants nothing

### 4. Deep Delegation

An attacker creates a deep delegation chain to obfuscate the
authority source.

**Defense:**
- The trust evaluator flags chains with `depth > 3` as an anomaly
  signal (lowering trust and biasing toward escalation)
- The chain detection module flags excessive depth and suspicious
  re-delegation patterns
- `delegation_depth` on the lease must be non-negative
- Note: subset-verified re-delegation (child lease bounded by parent)
  is designed but not implemented in the V1 gateway — see
  [Capability Lease API](../api/delegated_capabilities.md#delegation)

### 5. Self-Delegation

An agent attempts to delegate to itself to gain additional
authority.

**Defense:**
- The chain detector flags self-delegation patterns
- The delegation chain must have distinct issuer and subject at
  each level

### 6. Rapid Re-delegation

An attacker rapidly re-delegates to launder authority.

**Defense:**
- The chain detector monitors re-delegation frequency
- Rapid re-delegation triggers escalation

### 7. Issuer Concentration

A small number of issuers control a large number of leases.

**Defense:**
- The chain detector monitors issuer concentration
- High concentration is a signal of possible compromise

## Cryptographic Primitives

| Primitive | Use | Key Size | Library |
|-----------|-----|----------|---------|
| ed25519 | Identity signing | 256-bit | Go `crypto/ed25519` |
| SHA-256 | Chain lineage, digests | 256-bit | Go `crypto/sha256` |
| HMAC-SHA256 | Receipt signing | 256-bit (key) | Go `crypto/hmac` |

All primitives are from Go's standard library, which uses
audited implementations. We do not use custom crypto.

## Verification

The gateway evaluator performs:

1. **Lease signature verification** — ed25519 against the issuer's
   public key looked up from the `trusted_issuers` config registry.
   Unsigned leases and unknown issuers are rejected; the lease's
   embedded `verify_key` is not used for trust.
2. **Chain hash recomputation** — keyless SHA-256 over chain entries
   (integrity only)
3. **Expiry check** — current time < lease expiry
4. **Revocation check** — lease not in revocation list
5. **Scope check** — action in `allowed_actions` (exact or `*`) and
   resource equal to `resource_scope` (or `*`)

## Implementation

- [`identity/internal/crypto/`](../../identity/internal/crypto/) —
  Cryptographic primitives
- [`runtime/gateway/internal/identity/validator.go`](../../runtime/gateway/internal/identity/validator.go) —
  Gateway validator
- [`trust/internal/chain_detection/`](../../trust/internal/chain_detection/) —
  Chain pattern analysis

## Testing

```bash
cd identity && go test -race -count=1 ./...
cd ../trust && go test -race -count=1 ./internal/chain_detection/
cd ../runtime/gateway && go test -race -count=1 ./internal/identity/...
```

## Limitations

- **No post-quantum security.** ed25519 is vulnerable to Shor's
  algorithm on a sufficiently powerful quantum computer. Mitigation
  in V2+ may include hybrid signatures.
- **No revocation of the root identity.** Once an agent's key is
  established as a trusted root, only rotation (not revocation) can
  remove its trust. Mitigation: rotate root keys regularly.

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Capability Abuse](capability_abuse.md)
- [Identity API](../api/identity_api.md)
- [Capability Lease API](../api/delegated_capabilities.md)

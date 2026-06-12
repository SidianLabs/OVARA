# Capability Abuse

Capability abuse occurs when an agent uses a capability lease in
ways that exceed its granted permissions. This is the primary
defense surface for the identity module.

## Attack Patterns

### 1. Action Type Outside Scope

The agent has a lease for `git.pull` but attempts to run `shell`.

**Defense:** The gateway verifier checks `allowed_actions` against
the requested `action_type`. If the action is not in the list, the
decision is `deny` with reason `action_not_in_scope`.

### 2. Resource Outside Scope

The agent has a lease scoped to `repo:acme/api` but attempts to
access `repo:acme/other-service`.

**Defense:** The gateway verifier checks `resource_scope` against
the requested `resource` using glob matching. If the resource does
not match, the decision is `deny` with reason `resource_not_in_scope`.

### 3. Expired Lease

The agent has a valid lease but the lease has expired.

**Defense:** The gateway verifier checks `expiry` against the current
time. If the lease is expired, the decision is `deny` with reason
`lease_expired`.

### 4. Revoked Lease

The agent has a valid, non-expired lease but the lease has been
revoked by the issuer.

**Defense:** The gateway maintains a revocation list. If the lease
is in the revocation list, the decision is `deny` with reason
`lease_revoked`.

### 5. Forged Lease

The agent presents a lease that was not actually issued by the
claimed issuer.

**Defense:** The gateway verifier checks the ed25519 signature. If
the signature is invalid, the decision is `deny` with reason
`signature_invalid`.

### 6. Tampered Lease

The agent modifies a valid lease (e.g., changing `allowed_actions`
or extending `expiry`).

**Defense:** The gateway verifier checks the signature over the
canonical payload. Any modification invalidates the signature.

### 7. Replay Attack

The agent reuses a previously-captured lease request.

**Defense:** Each request includes a timestamp/nonce. The gateway
can detect replays if the same lease is used in rapid succession from
different IPs. (V2 feature; V1 trusts the lease alone.)

## Verification Flow

```
1. Reconstruct canonical payload from lease fields
2. Verify ed25519 signature against issuer's public key
3. Check current time < expiry
4. Check lease is not in revocation list
5. Check action_type is in allowed_actions
6. Check resource matches resource_scope
7. Check delegation chain (if any) for valid hash lineage
```

If any step fails, the decision is `deny` with a specific reason.

## Implementation

The verification logic is in
[`runtime/gateway/internal/identity/validator.go`](../../runtime/gateway/internal/identity/validator.go).
The lease structure is in
[`identity/internal/crypto/lease.go`](../../identity/internal/crypto/lease.go).

## Testing

The identity module has 66 test cases covering:

- Valid leases (positive cases)
- Expired leases
- Revoked leases
- Tampered leases (modified fields, invalid signatures)
- Forged leases (wrong issuer)
- Out-of-scope actions
- Out-of-scope resources
- Malformed leases

Run the tests:

```bash
cd identity && go test -race -count=1 ./...
cd ../runtime/gateway && go test -race -count=1 ./internal/identity/...
```

## Limitations

The V1 implementation trusts the issuer to be honest. A compromised
issuer can issue valid leases with overly-broad permissions. The
mitigation is to limit who can be an issuer (typically only the
gateway's own identity issuance service).

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Machine Identity Attacks](machine_identity_attacks.md)
- [Credential Abuse](credential_abuse.md)
- [Capability Lease API](../api/delegated_capabilities.md)

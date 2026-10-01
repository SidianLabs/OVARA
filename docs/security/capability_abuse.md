# Capability Abuse

Capability abuse occurs when an agent uses a capability lease in
ways that exceed its granted permissions. This is the primary
defense surface for the identity module.

## Attack Patterns

### 1. Action Type Outside Scope

The agent has a lease for `git.pull` but attempts to run `shell`.

**Defense:** The gateway verifier checks `allowed_actions` against
the requested `action_type` (exact match or `*`). If the action is not
in the list, the decision is `deny` with reason `capability_not_allowed`.

### 2. Resource Outside Scope

The agent has a lease scoped to `repo:acme/api` but attempts to
access `repo:acme/other-service`.

**Defense:** The gateway verifier checks `resource_scope` against
the requested `resource` using exact string matching (`*` matches all
resources — there is no glob expansion). If the resource does not
match, the decision is `deny` with reason `capability_scope_mismatch`.

### 3. Expired Lease

The agent has a valid lease but the lease has expired.

**Defense:** The gateway verifier checks `expiry` against the current
time. If the lease is expired, the decision is `deny` with reason
`capability_expired`.

### 4. Revoked Lease

The agent has a valid, non-expired lease but the lease has been
revoked by the issuer.

**Defense:** The gateway maintains a revocation list. If the lease
is in the revocation list, the decision is `deny` with reason
`capability_revoked`.

### 5. Forged Lease

The agent presents a lease that was not actually issued by the
claimed issuer.

**Defense:** The gateway verifier checks the ed25519 signature against
the issuer's public key from the `trusted_issuers` config registry.
Unsigned leases, unknown issuers, and invalid signatures all produce
`deny` (signature failures carry reason `identity_invalid`). The
lease's embedded `verify_key` is never used for trust.

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
2. Look up the issuer's public key in `trusted_issuers`; reject if
   the issuer is unknown or the lease is unsigned
3. Verify the ed25519 signature over the canonical payload
4. Check current time < expiry
5. Check lease is not in revocation list
6. Check action_type is in allowed_actions (exact or `*`)
7. Check resource equals resource_scope (exact or `*`)
8. Check delegation chain (if any) for valid integrity hash
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

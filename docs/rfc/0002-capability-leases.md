# RFC 0002: Capability Leases

## Summary

Introduce capability leases as the primitive for delegated machine authority.

## Requirements

- explicit issuer and subject
- bounded action and resource scope
- short-lived by default
- delegation depth limits
- revocation support
- signature verification

## Proposed Shape

```json
{
  "lease_id": "cap_123",
  "issuer": "usr_123",
  "subject": "agt_123",
  "actions": ["github.push"],
  "resources": ["repo:acme/api"],
  "expires_at": "2026-05-24T12:15:00Z",
  "max_delegation_depth": 0
}
```

## Tradeoffs

Leases reduce ambient authority, but require careful cache invalidation and fast
revocation propagation.


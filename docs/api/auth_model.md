# Authentication Model

Ovara uses a bearer token model for operator authentication. Agent
authentication uses ed25519-signed identity artifacts (leases,
delegation chains, trust metadata).

## Operator Authentication

Operators are humans or automation systems that manage the gateway
(approve escalations, recover stuck executions, manage policies, etc.).
Operator authentication uses bearer tokens.

### Token Format

```http
Authorization: Bearer <token>
```

Tokens are configured in [`etc/config.json`](../../runtime/gateway/etc/config.json):

```json
{
  "auth_enabled": true,
  "operator_tokens": [
    "sk_operator_<32+ random hex chars>"
  ]
}
```

### Token Generation

Generate a secure token with at least 32 bytes of entropy:

```bash
openssl rand -hex 32
# 64-char hex string
```

### Token Rotation

Tokens should be rotated at least every 90 days. Rotation procedure:

1. Generate a new token.
2. Add the new token to `operator_tokens` in config.
3. Reload the gateway (or wait for file watcher to pick up the change).
4. Update all clients/scripts to use the new token.
5. Remove the old token from the config.
6. Reload the gateway.

### Cloud API Key Format

The hosted control plane uses a different format for API keys:

```
ovara_<8-char-prefix>.<44-char-base64-secret>
```

The prefix is the first 8 characters of the SHA-256 hash of the
secret. This allows key validation without storing the secret itself.

Example:
```
ovara_a1b2c3d4.5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z
```

## Agent Authentication

Agents authenticate by presenting a valid `CapabilityLease` signed by
an authorized issuer. The gateway verifies the lease's ed25519
signature, checks the expiry, and validates the delegation chain
before granting any permissions.

### Verification Flow

```
┌──────────┐                  ┌──────────────┐                  ┌──────────────┐
│  Agent   │ ── request ────▶ │  Evaluator   │ ── verify sig ──▶ │  Lease Store │
│          │                  │              │ ◀───── valid ──── │  + Public Keys│
│          │                  │              │                   └──────────────┘
│          │                  │              │ ── check expiry ──▶ (in lease)
│          │                  │              │ ── check chain ───▶ (verify hashes)
│          │                  │              │ ── check revocation▶ (revocation list)
│          │ ◀── decision ─── │              │
└──────────┘                  └──────────────┘
```

### Issuer Trust

The gateway trusts lease issuers that are registered in the
configuration or the cloud control plane. Each issuer's public key is
stored alongside their identity.

For self-hosted deployments, issuers are configured via
[`identity/registry`](../../identity/internal/store/registry.go).
For cloud deployments, issuers register through the control plane.

## Authorization vs Authentication

Ovara separates these concerns:

- **Authentication** — proving the agent is who it claims to be (via
  lease signature verification)
- **Authorization** — deciding what the authenticated agent is
  allowed to do (via policy evaluation)

An agent with a valid signature but no matching policy rules still
receives an `escalate` decision (the policy is the authorization
layer). Conversely, an agent with a valid policy match but invalid
signature receives a `deny` decision (the signature is the
authentication gate).

## Security Best Practices

1. **Never commit tokens to version control** — use a secrets manager
   (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, etc.)
2. **Use different tokens for each environment** (dev, staging, prod)
3. **Use different tokens for each operator** when possible
4. **Rotate tokens at least every 90 days**
5. **Set `auth_enabled: true` in production**
6. **Use TLS for all network communication** (terminate at a reverse
   proxy or load balancer)
7. **Monitor auth events** — failed authentication attempts should
   trigger alerts

## Disabling Authentication (Local Development Only)

For local development only, set `auth_enabled: false` in the config.
This disables all authentication and is **never safe for production
deployments**.

```json
{
  "auth_enabled": false
}
```

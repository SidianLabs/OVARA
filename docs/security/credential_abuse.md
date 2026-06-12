# Credential Abuse

Credential abuse covers the theft, misuse, and lifecycle management
of the cryptographic credentials used by autonomous agents and
operator tokens.

## Threat Categories

### 1. Key Theft from Agent Host

An attacker compromises the host running the agent and steals the
private key from disk or memory.

**Defense:**
- Use hardware security modules (TPM, HSM) where available
- Store keys in OS-protected keyrings (Linux `keyctl`, macOS Keychain)
- Encrypt keys at rest with a passphrase or TPM-bound key
- Use memory-hard key derivation (Argon2id) for passphrases
- Limit key access to the agent process only (file permissions 0600)

### 2. Operator Token Theft

An attacker steals an operator bearer token from logs, config files,
or memory dumps.

**Defense:**
- Never log bearer tokens
- Store tokens in secrets managers, not in config files
- Use short-lived tokens where possible
- Rotate tokens at least every 90 days
- Use TLS for all network communication to prevent network sniffing
- Monitor for anomalous token usage (e.g., from unexpected IPs)

### 3. Token Replay

An attacker captures a valid token and replays it.

**Defense:**
- The gateway checks the source IP of each request (V2; V1 trusts
  the token alone)
- For high-security deployments, use mutual TLS for operator auth
- The hosted control plane uses API keys with a prefix-based lookup
  for fast revocation

### 4. Insecure Storage

An operator stores the bearer token in version control or a shared
filesystem with weak permissions.

**Defense:**
- Never commit tokens to git
- Use `.gitignore` to exclude `etc/config.json` from version control
- Use deployment automation (Ansible Vault, Helm Secrets) to inject
  tokens at deploy time
- Audit token storage periodically

## Recommended Practices

### For Operators

1. **Generate tokens with sufficient entropy**
   ```bash
   openssl rand -hex 32  # 64-char hex string, 256 bits
   ```

2. **Use different tokens per environment**
   - `sk_dev_*` for development
   - `sk_staging_*` for staging
   - `sk_prod_*` for production

3. **Use different tokens per operator**
   - When possible, give each operator a unique token
   - This enables per-operator audit trails
   - When an operator leaves, only their token needs to be revoked

4. **Rotate tokens regularly**
   - At least every 90 days
   - Immediately on suspected compromise
   - Document rotation in a runbook

5. **Monitor token usage**
   - Log all auth events (success and failure)
   - Alert on unusual patterns (off-hours use, foreign IPs, etc.)

### For Agent Identity

1. **Use hardware-backed key storage**
   - TPM 2.0 on Linux
   - Secure Enclave on macOS
   - Windows CNG/CNG-NG

2. **Use short-TTL leases**
   - Default: 1 hour
   - Sensitive actions: 15 minutes
   - Long-running workflows: delegate as needed

3. **Monitor for anomalous key usage**
   - Sudden increase in actions per minute
   - Actions from unexpected IPs
   - Actions outside normal scope

4. **Plan for key rotation**
   - Have a documented procedure
   - Test the procedure periodically
   - Communicate rotation windows to dependents

## Incident Response

### Suspected Token Compromise

1. **Revoke the token immediately** by removing it from
   `operator_tokens` in the config
2. **Reload the gateway** to apply the change
3. **Review audit logs** for actions taken with the compromised token
4. **Generate a new token** and distribute to legitimate operators
5. **Document the incident** in the security incident log

### Suspected Key Compromise

1. **Revoke all leases** issued to the compromised agent
2. **Suspend the agent** in the identity registry
3. **Generate a new key pair** for the agent
4. **Re-issue leases** under the new key
5. **Review the delegation chain** to identify potential spread
6. **Document the incident**

## Implementation References

- Token configuration: [`etc/config.json`](../../runtime/gateway/etc/config.json)
- Auth middleware: [`runtime/gateway/internal/auth/`](../../runtime/gateway/internal/auth/)
- Key generation: [`identity/internal/crypto/identity.go`](../../identity/internal/crypto/identity.go)

## Related Documents

- [Security Policy](../../SECURITY.md) — vulnerability disclosure
- [Machine Identity Attacks](machine_identity_attacks.md)
- [Capability Abuse](capability_abuse.md)
- [Authentication Model](../api/auth_model.md)

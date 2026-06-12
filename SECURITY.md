# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Ovara, **please do not open a
public issue**. Email [security@ovara.dev](mailto:security@ovara.dev) with
the details and we will respond within 72 hours.

When reporting, please include:

- Description of the vulnerability and its impact
- Reproduction steps with the smallest possible policy + request
- Affected component(s) and version
- Your name/handle for credit (optional)

We follow **coordinated disclosure**: we will work with you to understand
the issue, develop a fix, and agree on a disclosure timeline. We aim to
acknowledge within 72 hours and ship a fix within 30 days for critical
issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |
| 0.x     | ❌ End of life — please upgrade |

## Security Architecture

Ovara is a runtime trust layer for autonomous systems. Its security model
is built on defense-in-depth across four independent layers:

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│  ┌───────────────────────────────────────────────────┐  │
│  │              AppArmor Profile                      │  │
│  │  Capability restrictions, file access control,     │  │
│  │  network restrictions, deny ptrace/dbus/mount      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Seccomp Filter                        │  │
│  │  Whitelist of ~130 syscalls, blocks mount, ptrace, │  │
│  │  kexec, bpf, module loading                       │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │              eBPF Interceptor                      │  │
│  │  Runtime syscall monitoring, policy enforcement,   │  │
│  │  audit trail via ring buffer                       │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────┐  │
│  │              Firecracker MicroVM                    │  │
│  │  Hardware isolation via KVM, read-only rootfs,     │  │
│  │  resource limits, network isolation                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

Ovara uses well-audited cryptographic primitives:

| Primitive | Use | Library |
|-----------|-----|---------|
| ed25519 | Identity signing (AgentIdentity, CapabilityLease, CrossOrgReceipt) | Go `crypto/ed25519` |
| HMAC-SHA256 | Receipt signing | Go `crypto/hmac` + `crypto/sha256` |
| SHA-256 | Action digests, delegation chain lineage, identity digests | Go `crypto/sha256` |
| PBKDF2 | API key derivation (where applicable) | Go `crypto/pbkdf2` |

All cryptographic code is reviewed by maintainers before merge. See
`docs/security/` for threat-model documentation.

## Operator Token Hygiene

Operator tokens in `etc/config.json` are bearer tokens that grant full
admin access. We recommend:

- Store in a secrets manager, not in version control
- Rotate at least every 90 days
- Use a token with at least 32 bytes of entropy (`openssl rand -hex 32`)
- Use separate tokens per environment and per operator
- Revoke compromised tokens immediately via the control plane API

## Receipt Signing Key

The `receipt_signing_key` config field controls HMAC-SHA256 receipt
signing. If unset, the gateway falls back to `gateway_id` as the key,
which is **not cryptographically strong**. For production deployments:

```json
{
  "receipt_signing_key": "$(openssl rand -hex 32)"
}
```

## Disclosure History

No vulnerabilities disclosed to date.

## Acknowledgments

We thank the security researchers and contributors who have helped make
Ovara more secure.

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
| 2.0-RC1 | ✅ Release candidate — security freeze |
| 1.0.x   | ✅ Active |
| 0.x     | ❌ End of life — please upgrade |

## Security Architecture

Ovara is a runtime trust layer for autonomous systems. Its security model
is built on defense-in-depth across four independent layers.

> **RC1 status**: the gateway authorization chain (identity → delegation
> → lease → policy → approval → execution → evidence) and the egress
> proxy (MITM + credential injection + scrubbing + signed receipts) are
> implemented and clean-room verified — see
> `docs/OVARA_RC1_SECURITY_REPORT.md`. The kernel-level layers below
> (AppArmor/seccomp/eBPF/Firecracker) are the hardening path, not the
> current default deployment.

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
| ed25519 | Delegation hop signatures, capability lease signatures, proxy receipt-chain signatures, trusted-issuer verification | Go `crypto/ed25519` |
| HMAC-SHA256 | Gateway receipt signing (`receipt_signing_key`) | Go `crypto/hmac` + `crypto/sha256` |
| SHA-256 | Action digests, delegation replay keys, credential-derived principal IDs, canonical encoding | Go `crypto/sha256` |

Canonical signing format: all signed delegation/lease payloads use a
length-prefixed binary encoding (`u32be(len)||bytes` per field,
`u32be(count)` arrays, `i64be` timestamps) implemented identically in
`runtime/gateway/internal/identity/canon.go` and
`sdk/python/src/ovara_sdk/canon.py` — cross-verified byte-for-byte,
including Python-signed two-hop chains verified by Go.

## Identity & Authorization Model (P1/P1.1)

- **Credential-derived principals**: the authoritative identity is
  `ag_<sha256(token)[:16]>` / `op_<…>`, stamped by the auth middleware.
  Caller-supplied `agent_identity.subject_id` must equal it or the
  request is rejected with HTTP 400 `identity_mismatch`.
- **Delegation chains** (capability, not attestation): ed25519-signed
  hops verified against a configured `trusted_issuers` registry; chain
  linkage `issuer[i+1] == subject[i]`; terminal subject must equal the
  authenticated principal; non-amplification enforced; replay keyed on
  the terminal hop's *signed* nonce (in-memory, 5-minute window —
  process-local, not durable). A valid chain narrows the request; it
  can never lift policy.
- **Capability leases**: ed25519-signed, issuer-verified; require exact
  audience match to the gateway identity; subject must equal the
  authenticated principal; action+resource scope enforced.
- **Policy**: independent last gate — escalation is never lifted by
  valid credentials.
- **Approvals**: bound to the gateway-recorded decision (not caller
  fields), single-use resume, owner-or-operator only.

All cryptographic code is reviewed by maintainers before merge. See
`docs/OVARA_2_THREAT_MODEL.md` and `docs/OVARA_RC1_SECURITY_REPORT.md`.

## Operator Token Hygiene

Operator tokens in `etc/config.json` are bearer tokens that grant full
admin access. We recommend:

- Store in a secrets manager, not in version control
- Rotate at least every 90 days
- Use a token with at least 32 bytes of entropy (`openssl rand -hex 32`)
- Use separate tokens per environment and per operator
- On compromise: replace the token in config and restart the gateway —
  tokens are static config-file credentials in RC1 (no runtime token
  revocation API; credential lifecycle is deferred work)

## Receipt Signing Key

The `receipt_signing_key` config field controls HMAC-SHA256 receipt
signing. If unset, the gateway generates a **random per-process key**
at startup and logs a warning — receipts signed under it cannot be
verified after a restart (see `server.go`). For production deployments:

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

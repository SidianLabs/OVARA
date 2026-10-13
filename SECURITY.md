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

Ovara is pre-release. Security fixes land on `main` first and go into the
next 0.9.x release.

| Version | Supported |
|---------|-----------|
| `main` (unreleased) | Yes: fixes land here first |
| 0.9.x | Yes: the current pre-release line |
| Anything older, including the withdrawn `v1.0.0` tag and the "2.0-RC1" label in older documents | No |

Each guarantee Ovara makes, the mode it holds in, and the test behind it
are listed in [`docs/GUARANTEES.md`](docs/GUARANTEES.md).

## Security Architecture

Ovara is a runtime trust layer for autonomous systems. Its security model
combines a gateway authorization chain, an egress proxy, and (optionally)
an enforced network boundary. Only the first two are built into the `ovara`
binary; the kernel-level layers shown in the diagram below are a **design
target, not a shipped feature**.

> **RC1 status**: the gateway authorization chain (identity → delegation
> → lease → policy → approval → execution → evidence) and the egress
> proxy (MITM + credential injection + scrubbing + signed receipts) are
> implemented and clean-room verified — see
> `docs/OVARA_RC1_SECURITY_REPORT.md`. The kernel-level layers below
> (AppArmor/seccomp/eBPF/Firecracker) are NOT implemented in the gateway
> (it has a Docker sandbox for command execution, nothing more); they are the
> hardening path, not the
> current default deployment.
>
> **What contains the agent today** depends on the mode. In *cooperative*
> mode (`ovara env`) the agent is only asked to use the proxy; a hostile
> agent can ignore it. If the agent runs as the same OS user as Ovara it can
> also read Ovara's keys and edit its policy and log; run it as a different
> user. *Enforced* mode (`--boundary`, Linux) removes the network path
> around the proxy. `ovara box` (Linux) adds a separate user, its own root
> file system or a container, and a check of every command the agent
> runs. `ovara doctor` reports which of these hold.
>
> Target design (not built):

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
| ed25519 | Delegation hop signatures, capability lease signatures, trusted-issuer verification, signed journal envelopes | Go `crypto/ed25519` |
| ed25519 (`sig_v2`, `sig_v1`) | Proxy receipt chain (`var/receipts.jsonl`); v2 format below, v1 still verifies | Go `crypto/ed25519` |
| ed25519 (`edsig_v1`) | Gateway receipt signatures: domain-separated, length-prefixed preimage covering every receipt field (and `policy_hash` when present); receipts issued after their key was revoked, or after a replaced key's rotation grace, are rejected | Go `crypto/ed25519` |
| HMAC-SHA256 (`hmac_v1`) | Legacy gateway receipt signing (`receipt_signing_key`), kept alongside `edsig_v1`. Its prefix was `sig_v1:` before October 2026 and was renamed so it can never be mistaken for a proxy signature. It is never reported as a valid receipt signature on its own | Go `crypto/hmac` + `crypto/sha256` |
| SHA-256 | Action digests, delegation replay keys, credential-derived principal IDs, canonical encoding | Go `crypto/sha256` |

Canonical signing format: all signed delegation/lease payloads use a
length-prefixed binary encoding (`u32be(len)||bytes` per field,
`u32be(count)` arrays, `i64be` timestamps) implemented identically in
`runtime/gateway/internal/identity/canon.go` and
`sdk/python/src/ovara_sdk/canon.py` — cross-verified byte-for-byte,
including Python-signed two-hop chains verified by Go.

## Proxy receipts (format v2)

Every request that reaches the proxy leaves a receipt in
`var/receipts.jsonl`, one JSON object per line, each linked to the one
before by `prev_hash` (SHA-256 of the previous line's bytes).

- **Attempt and outcome.** A request that goes upstream gets an attempt
  receipt (`phase: "attempt"`), appended and synced to disk before the
  first byte is sent, and an outcome receipt (`phase: "outcome"`, with
  `attempt_id`) before the response reaches the agent. If the attempt
  receipt cannot be written, the request is refused. A request that never
  goes upstream gets one receipt with no phase.
- **Fields** (`"v": 2`): `receipt_id`, `session_id`, `timestamp`,
  `method`, `url`, `decision`, `status`, `approval_id`, `phase`,
  `outcome`, `attempt_id`, `agent` (`pt_` + the first 16 hex of the
  SHA-256 of the proxy token), `rule` (the policy rule that decided),
  `policy_hash`, `approver`, `req_bytes`, `resp_bytes`, `body_sha256`,
  `reasons`, `kid` (the signing key), `prev_hash`, `signature`.
- **What is signed.** `signature` is `sig_v2:` + hex Ed25519 over this
  byte string: `"ovara-proxy-receipt-v2\n"`, then for each field in the
  order `v, receipt_id, session_id, timestamp (Unix nanoseconds), method,
  url, decision, status, approval_id, phase, outcome, attempt_id, agent,
  rule, policy_hash, approver, req_bytes, resp_bytes, body_sha256,
  reasons, kid, prev_hash`: a 4-byte big-endian length and the field
  name, then a 4-byte big-endian length and the value. Numbers are
  decimal. `reasons` is written as its count, followed by each reason
  as a length and its bytes. Every value is length-prefixed, so no two
  receipts share a signed byte string.
- **Strict lines.** A line must be exactly the JSON encoding of what it
  decodes to. Unknown, duplicate or reordered keys and changed whitespace
  are refused.
- **v1.** Older receipts (`sig_v1:`, a pipe-joined payload) still verify.
  A chain may hold v1 receipts and then v2 ones, never v1 after v2. A v1
  line that carries v2 fields is refused, because v1 does not sign them.
  An outcome receipt must follow its attempt.
- **Anchors.** `var/anchors.jsonl` records the chain head as it grows. A
  log that was cut short, or cut and continued, fails verification, and
  `ovara run` refuses to append to it.

### Receipt key history, rotation and revocation

The proxy's public keys are kept in `var/receipt_keys.jsonl`
(`kid`, public key, `not_before`, `not_after`, `revoked_at`). A receipt is
checked against the key its `kid` names, and is refused if it is dated
outside that key's window or at or after its revocation.

```bash
ovara keys list-receipt   -dir mydir
ovara keys rotate-receipt -dir mydir                  # stop ovara run first
ovara keys revoke-receipt -dir mydir -key <kid> -at <RFC 3339 time it may have leaked>
```

The proxy will not start with a retired or revoked key, and will not make
a new key over an existing log when the key file is missing. Revocation
stops later-dated forgeries; a stolen key can still sign receipts dated
before the revocation time. `ovara log -verify-only`, `ovara log export`,
`ovara incident bundle`, `ovara doctor` and `ovara-proxy -verify` all use
the key history.

## Gateway journals and recovery

- **Journal envelopes v2.** Each signed journal line covers its version,
  its links and its signing time (`at`), besides the record. Lines are
  decoded strictly (unknown or duplicate keys are refused, and v2 lines
  must be byte-canonical). `at` never goes backwards. v1 journals still
  open; a v1 line after a v2 line is refused. A complete line that fails
  the strict check is reported as corruption, never trimmed away as a
  torn tail.
- **Key state.** An envelope signed at or after its key was revoked or
  destroyed, or after a replaced key's rotation grace, fails to open (v2
  envelopes only; v1 envelopes carry no time).
- **No receipt, no allow.** If the gateway cannot store a receipt, an
  allow or escalate becomes a deny with the reason `receipt_unavailable`.
- **Outcome unknown.** An action that was running when the gateway
  stopped is recovered as `executed` with `outcome_unknown: true`. It is
  never retried automatically; a person has to check what happened.
- **Owner-only files.** Stores, journals, logs and keys are written 0600
  in 0700 directories. `ovara init` writes `policy.json` 0600 and no
  longer prints the operator token (it is in `config.json`).

## Identity & Authorization Model (P1/P1.1)

- **Credential-derived principals**: the authoritative identity is
  `ag_<sha256(token)[:16]>` / `op_<…>`, stamped by the auth middleware.
  Caller-supplied `agent_identity.subject_id` must equal it or the
  request is rejected with HTTP 400 `identity_mismatch`.
- **Delegation chains** (capability, not attestation): ed25519-signed
  hops verified against a configured `trusted_issuers` registry; chain
  linkage `issuer[i+1] == subject[i]`; terminal subject must equal the
  authenticated principal; non-amplification enforced; replay keyed on
  the terminal hop's *signed* nonce (5-minute window; durable across
  restarts when `replay_file` is configured, which `ovara init` does —
  process-local otherwise). A valid chain narrows the request; it
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
  tokens in `config.json` are static credentials and cannot be revoked
  without a restart. Credentials held in the identity registry
  (`identity_registry_file`) can be revoked at runtime.

## Failure behaviour

The gateway fails closed. A configured persistent store (receipts,
approvals, continuations, executions, events, capabilities) that cannot be
opened stops startup rather than continuing with an empty in-memory store;
an approved action whose "executing" claim cannot be written to disk is not
run. Recovering from a corrupt or tampered journal is a deliberate operator
step (inspect, then move the file aside), never an automatic one.

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

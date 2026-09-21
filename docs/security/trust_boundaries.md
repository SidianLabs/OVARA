# Trust Boundaries

A trust boundary is a point in the system where the level of trust
changes. Identifying trust boundaries is essential for threat
modeling and security review.

## Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    OUTSIDE TRUST BOUNDARY                        │
│  - Untrusted user input                                          │
│  - Untrusted LLM output                                          │
│  - Untrusted network traffic                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │ (intercepted by gateway)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    INSIDE TRUST BOUNDARY                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  GATEWAY (trusted)                         │   │
│  │  - Receives action requests                                │   │
│  │  - Verifies identity + lease                              │   │
│  │  - Evaluates policy                                       │   │
│  │  - Decides allow/deny/escalate                            │   │
│  │  - Produces signed receipt                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                     │
│                             ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              TARGET SYSTEM (semi-trusted)                  │   │
│  │  - Receives approved actions                              │   │
│  │  - Executes shell/git/github/ci commands                  │   │
│  │  - Returns results                                         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                     │
│                             ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              CONTROL PLANE (trusted)                      │   │
│  │  - Distributes policies                                   │   │
│  │  - Manages tenant isolation                               │   │
│  │  - Issues identity / leases                               │   │
│  │  - Collects audit logs                                    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Trust Boundaries in Detail

### 1. Network Trust Boundary

The gateway separates trusted and untrusted network traffic:

- **Inbound to the gateway:** Untrusted. The gateway serves plain
  HTTP — there is no TLS in the binary. Deployments must terminate
  TLS in front (reverse proxy or load balancer). All requests are
  validated against policy.
- **Outbound to control plane:** Trusted. Uses TLS with certificate
  pinning in V2.
- **Outbound to target systems:** Semi-trusted. Only allowed for
  actions that pass policy.

**Mitigation:** TLS terminated in front of the gateway for all network
communication. Mutual TLS for operator auth in high-security
deployments is a future option.

### 2. Process Trust Boundary

The gateway process is trusted; the agent process is not:

- **Gateway process:** Runs as the `ovara` user with AppArmor
  profile applied
- **Agent process:** Runs in a separate container or VM, with
  limited capabilities
- **Communication:** The agent sends action requests via HTTP;
  the gateway decides and (if allowed) the agent executes

**Mitigation:** The agent cannot directly invoke the gateway's
internal functions. All communication is via the HTTP API.

### 3. Identity Trust Boundary

The verifiable artifact is the `CapabilityLease`; the `AgentIdentity`
on a request is self-asserted:

- **AgentIdentity:** Self-asserted. The gateway validates structure
  only (issuer and subject_id present, length bounds). It carries no
  signature and grants nothing by itself.
- **CapabilityLease:** Verified. The lease must carry an ed25519
  signature that verifies against the issuer's public key in the
  gateway's `trusted_issuers` config registry. Unsigned leases and
  unknown issuers are rejected.
- **DelegationChain:** Integrity-checked. The keyless SHA-256
  `chain_hash` detects corruption; entries are not signed, so the
  chain alone proves nothing about authority.
- **External (cross-org):** Semi-trusted. The trust graph tracks
  the level of trust between organizations.

**Mitigation:** Lease signature verification against `trusted_issuers`
is mandatory before any lease-derived authorization applies.

### 4. Policy Trust Boundary

Policies in the policy store are trusted; arbitrary JSON in
request bodies is not:

- **Policy file (etc/policy.json):** Trusted. Loaded at startup
  and hot-reloaded via file watcher.
- **Policy from control plane:** Trusted. Distributed via signed
  policy distribution.
- **Request metadata:** Not trusted. Metadata is for audit
  purposes only; it does not affect policy evaluation.

**Mitigation:** Policy changes are atomic (whole file swap). The
gateway validates policy structure at load time.

### 5. Operator Trust Boundary

The gateway has a single operator privilege level: any valid bearer
token has full operator access. There is no RBAC on the gateway —
there are no separate admin, approver, or read-only roles in the V1
binary.

- **Gateway:** Flat bearer tokens; one privilege level.
- **Control plane:** API keys carry organization scope, which isolates
  orgs from each other; finer-grained key scopes are limited.

**Mitigation:** Treat every operator token as full-access, scope
physical access to the gateway accordingly, and rely on the audit log
for accountability.

## Crossing Trust Boundaries

Each cross-boundary interaction has a defined protocol:

| Boundary | Protocol | Authentication | Authorization |
|----------|----------|----------------|---------------|
| Agent → Gateway | HTTP/JSON (TLS terminated in front) | Lease signature vs `trusted_issuers` | Policy evaluation |
| Gateway → Control Plane | HTTPS required by default | API key | Org scope |
| Operator → Gateway | HTTP/JSON | Bearer token | Token presence (single level) |
| Cross-org | HTTP/JSON | Trust graph | Path verification |

## Defense in Depth

Trust boundaries should be enforced at multiple levels:

```
Network → Process → Identity → Policy → Application
TLS in  Caps      Crypto    Rules    Code
front
```

A single layer failing should not be sufficient to compromise the
system. Each layer provides independent protection.

## Threat Modeling

When designing new features, identify the trust boundaries the
feature crosses:

1. Where does data enter the system? (Untrusted input)
2. Where is data validated? (Trust boundary crossing)
3. Where is data stored? (Trusted storage)
4. Where is data output? (Trust boundary crossing on egress)

Each crossing should be explicit, validated, and logged.

## Related Documents

- [Attack Vectors](attack_vectors.md) — threat model
- [Runtime Containment](runtime_containment.md) — defense layers
- [Authentication Model](../api/auth_model.md) — operator auth

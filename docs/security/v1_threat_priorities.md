# V1 Threat Priorities

This document ranks the threat vectors that the Ovara V1 release
focuses on defending against. It is the basis for the V1 threat model
and the V1 security test plan.

## P0 — Must Defend in V1

These threats are the primary justification for Ovara's existence.
If any of these are not defended, Ovara is not a viable product.

### 1. Prompt Injection → Privilege Escalation
- **Risk:** Critical
- **Likelihood:** High
- **Defense:** Policy enforcement on every action, no privilege
  escalation possible from the agent's runtime
- **Tested by:** Phase 67 trust-aware security tests

### 2. Capability Abuse
- **Risk:** Critical
- **Likelihood:** High
- **Defense:** Cryptographic capability lease verification, scope
  enforcement
- **Tested by:** Identity module tests (66 test cases)

### 3. Credential Theft
- **Risk:** High
- **Likelihood:** Medium
- **Defense:** Short-TTL leases, immediate revocation, secure key
  storage
- **Tested by:** Revocation tests in `capabilities/file_store_test.go`

### 4. Runtime Containment Failure
- **Risk:** Critical
- **Likelihood:** Low
- **Defense:** AppArmor + seccomp + eBPF + Firecracker defense-in-depth
- **Tested by:** Security profile validation
  (`security/apparmor/`, `security/sandbox/`)

## P1 — Should Defend in V1

These threats are important but not as common as P0.

### 5. Long-Horizon Drift
- **Risk:** High
- **Likelihood:** Medium (increases with deployment duration)
- **Defense:** DriftDetector, DegradationModel, trust-dependent rules
- **Tested by:** Phase 67 trust tests

### 6. Delegation Chain Forgery
- **Risk:** High
- **Likelihood:** Low
- **Defense:** SHA-256 hash lineage verification, ed25519 signatures
- **Tested by:** `identity/internal/crypto/delegation_test.go`

### 7. Recursive Execution (Gateway Bypass)
- **Risk:** High
- **Likelihood:** Low
- **Defense:** All execution surfaces routed through gateway,
  AppArmor prevents bypass
- **Tested by:** Shell interceptor tests, AppArmor profile validation

## P2 — Nice to Defend in V1

These threats are emerging or low-likelihood. They are documented but
full defense may be in V2.

### 8. Autonomous Exploitation
- **Risk:** Medium
- **Likelihood:** Low
- **Defense:** Trust monitoring, shield auto-restriction
- **Status:** Basic defense in V1, advanced in V2

### 9. Cross-Org Trust Compromise
- **Risk:** Medium
- **Likelihood:** Low
- **Defense:** TrustGraph with revocation, cross-org receipt
  verification
- **Status:** Implemented in V1 (Phase 74), tested in trust module

## Out of Scope for V1

These threats are explicitly out of scope for V1:

- **Side-channel attacks on signing** (timing attacks, cache attacks) —
  mitigated by Go's crypto library but not specifically tested
- **Quantum attacks on ed25519** — ed25519 is not post-quantum; this
  is a V2+ concern
- **Internal threat (malicious operator)** — operators have full
  admin access by design; mitigation is procedural (audit logs, MFA
  on operator systems)
- **DDoS on the gateway** — the gateway is local-first and not
  directly exposed to the internet; DDoS is a deployment concern

## Threat Model Update Process

The threat model is reviewed quarterly. New threats are added when:

1. A real-world attack is reported against autonomous systems
2. A new feature adds a new attack surface
3. A customer reports a security concern
4. A security researcher submits a vulnerability report

See [`SECURITY.md`](../../SECURITY.md) for the vulnerability disclosure
process.

## Security Test Plan

The V1 security test plan covers:

- [ ] Prompt injection (via simulated adversarial prompts)
- [ ] Capability abuse (via test cases in `identity/`)
- [ ] Credential theft (via revocation tests)
- [ ] Runtime containment (via AppArmor/seccomp/eBPF profile
  validation)
- [ ] Drift detection (via Phase 67 trust tests)
- [ ] Chain detection (via `chain_detection_test.go`)
- [ ] Trust degradation (via `degradation_test.go`)
- [ ] Receipt forgery (via `signer_test.go`)

Automated security tests run in CI via `.github/workflows/go-tests.yml`.
Manual penetration testing is recommended before any production
deployment.

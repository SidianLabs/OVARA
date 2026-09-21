# Ovara Roadmap

## Phase 1: Trusted Interception ✅ COMPLETE

Goal: make sensitive AI actions interceptable, policy-evaluable, and auditable.

- ✅ shell, GitHub, Git, and CI/CD action interceptors (11 execution surfaces)
- ✅ local policy engine with allow, deny, and escalate outcomes
- ✅ approval workflows for high-risk actions (create, audit, enforce, escalate)
- ✅ execution receipts with cryptographic signing (HMAC-SHA256)
- ✅ operator bearer-token auth, bulk retry/cancel, unified pagination
- ✅ SLA health diagnostics, stuck-executing recovery, panic recovery
- ✅ runtime SDKs for TypeScript and Python (separate codebases)

Exit criteria:

- ✅ sub-50 ms policy path for cached policy decisions
- ✅ verifiable audit log for all gated actions
- ✅ usable local developer runtime (23/23 packages passing under -race)

## Phase 2: Machine Identity ✅ COMPLETE

Goal: give autonomous systems attributable, scoped, revocable identity.

- ✅ agent identity issuance (ed25519 key pairs, lifecycle: active/suspended/revoked)
- ✅ capability leases with expiration and revocation (ed25519-signed, TTL-based)
- ✅ delegated authority chains (hash-verified lineage, depth-bounded)
- ✅ signed execution receipts (Phase 1 signer delivers this)
- ✅ trust metadata — signed runtime/posture attestation
- ✅ agent registry with suspend/revoke/lifecycle management
- ✅ capability lease store with subject/issuer filtering
- ✅ identity issuer service orchestrating registration + lease issuance
- ✅ cryptographic CapabilityLease signature verification in gateway validator
- ✅ 66 test cases, 0 data races

## Phase 3: Trust-Aware Security

Goal: shift from static authorization to behavior-aware runtime trust.

- deterministic anomaly heuristics
- trust degradation and recovery models
- drift detection across long-running agents
- suspicious capability chaining detection
- policy rules that depend on trust state for escalation first, hard deny later

## Phase 4: Enterprise Cloud

Goal: operate Ovara as resilient infrastructure.

- hosted control plane
- regional runtime gateways
- tenant isolation
- enterprise federation
- compliance exports and governance tooling

## Phase 5: Federated Trust Network

Goal: establish Ovara as trust infrastructure for machine actors.

- cross-organization machine identity federation
- portable execution receipts
- trust graph APIs
- delegated machine authority protocols

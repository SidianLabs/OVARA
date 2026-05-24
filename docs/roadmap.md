# Ovara Roadmap

## Phase 1: Trusted Interception

Goal: make sensitive AI actions interceptable, policy-evaluable, and auditable.

- runtime SDKs for TypeScript and Python
- shell, GitHub, Git, and CI/CD action interceptors
- local policy engine with allow, deny, and escalate outcomes
- approval workflows for high-risk actions
- OpenTelemetry-based tracing and execution receipts

Exit criteria:

- sub-50 ms policy path for cached policy decisions
- verifiable audit log for all gated actions
- usable local developer runtime

## Phase 2: Machine Identity

Goal: give autonomous systems attributable, scoped, revocable identity.

- agent identity issuance
- capability leases with expiration and revocation
- delegated authority chains
- signed execution receipts
- target-side trust metadata verification

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

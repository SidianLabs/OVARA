# Phase Plan

This is the canonical implementation sequence for Ovara.

## Phase 0: Repo Foundation

Objective:
create the monorepo, core documentation set, ADR baseline, and repo conventions.

Deliverables:

- repository structure
- architecture docs
- PRD set
- initial roadmap

Status:

- completed

## Phase 1: Runtime Gateway Core

Objective:
establish the first real execution control point.

Required deliverables:

- runtime gateway service scaffold
- canonical action request schema
- canonical decision response schema
- local decision engine interface
- basic decision logging
- health and configuration surfaces

Exit criteria:

- agent actions can be normalized and evaluated through one gateway path
- decision responses are deterministic for the same input and policy snapshot
- the system is runnable locally

Non-goals:

- advanced trust scoring
- identity federation
- complex multi-tenant cloud features

## Phase 2: SDK Interceptors

Objective:
make the gateway usable from real agent systems.

Required deliverables:

- TypeScript SDK interceptor
- Python SDK interceptor
- shell adapter
- Git/GitHub adapter
- CI/CD trigger adapter

Exit criteria:

- protected actions can be intercepted from TypeScript and Python examples
- action metadata is rich enough for policy evaluation

## Phase 3: Policy And Approval

Objective:
turn interception into enforceable runtime control.

Required deliverables:

- policy model
- policy evaluator
- allow/deny/escalate outcomes
- approval workflow service
- policy simulation examples

Exit criteria:

- risky actions can be escalated to approval
- policy evaluation is testable and explainable

## Phase 4: Observe And Receipts

Objective:
make actions attributable and inspectable.

Required deliverables:

- receipt schema implementation
- receipt signer/verifier
- OpenTelemetry integration
- execution event pipeline
- local trace/receipt inspection flow

Exit criteria:

- every critical action produces a receipt
- receipt verification works locally

## Phase 5: Identity And Delegation

Objective:
replace ambient authority with explicit machine authority.

Required deliverables:

- agent identity model
- capability lease model
- delegation chain validation
- revocation hooks

Exit criteria:

- actions can be evaluated against explicit machine identity and scoped
  capability leases

## Phase 6: Shield Signals

Objective:
introduce first-generation runtime security without making the hot path opaque.

Required deliverables:

- deterministic anomaly heuristics
- trust context enrichment
- escalation hooks
- containment action interface

Exit criteria:

- suspicious actions can trigger escalation or containment recommendations

## Phase 7: Hosted Control Plane

Objective:
make Ovara operable as a managed platform.

Required deliverables:

- policy distribution
- approval management
- receipt storage
- tenant model
- gateway enrollment

Exit criteria:

- self-hosted runtime can connect to a hosted control plane


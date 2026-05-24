# Runtime PRD

## Problem

Autonomous coding and operations agents are increasingly able to execute shell
commands, modify repositories, and trigger deployments with little runtime
control. Most current safety mechanisms are advisory, static, or bolted on
after the action has already happened.

## Goals

- intercept sensitive actions before execution
- return allow, deny, or escalate decisions in real time
- keep p95 local decision latency under 75 ms
- produce verifiable execution receipts
- make the initial product usable in real engineering workflows within one day

## V1 Scope

V1 only supports:

- shell command execution
- GitHub and Git mutation actions
- CI/CD deployment triggers
- human approval for high-risk actions

## Explicit Non-V1 Scope

These are intentionally out of scope for the first production wedge:

- payments and financial execution
- browser automation governance
- broad database mutation support
- enterprise identity federation
- learned anomaly models in the decision hot path
- fully autonomous containment

## Non-Goals

- replacing existing workflow engines
- building a general-purpose agent framework
- replacing enterprise IAM
- becoming a generic compliance console

## Architecture

- SDK interceptors capture action intents
- runtime gateway normalizes action requests
- policy engine evaluates identity, capability, context, and trust
- receipt service records signed outcomes

## Product Principles

- the decision must happen before the side effect
- the platform must be deployable without re-architecting the agent system
- every consequential action must be attributable after the fact
- v1 trust signals may escalate decisions, but should be conservative about
  hard deny based on behavioral inference alone

## UX Flows

- agent requests action
- runtime evaluates
- action is allowed, denied, or sent to approval

## API Requirements

- action check endpoint
- approval callback endpoint
- receipt query endpoint

## Scaling Concerns

- hot path needs in-memory policy/cache
- write-heavy event ingestion
- multi-tenant isolation
- revocation changes must propagate faster than ordinary telemetry

## Threat Models

- bypassed interceptors
- replayed requests
- forged agent context
- approval spoofing
- abuse of overly broad policy defaults

## Adoption Strategy

- start with agentic coding and DevOps workflows where shell, Git, GitHub, and
  deployment actions already concentrate risk and value

## Failure Modes

- fail closed for production mutations when the gateway cannot evaluate policy
- allow explicit fail-open only for low-risk local development actions
- cached policy may be used during control-plane degradation, but revoked
  capabilities must invalidate cache immediately

## Rollout Strategy

- local runtime
- hosted control plane beta
- enterprise regional gateways

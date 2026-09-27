# OVARA Documentation Index

Every doc in this tree, mapped to the question it answers. Newcomers:
start with the root [README](../README.md), then
[developer/getting_started.md](developer/getting_started.md).

Two conventions used below:

- **Checkpoint / pass / phase docs** (`docs/build/phase_*`,
  `docs/OVARA_2_*`, `docs/architecture/runtime_*_pass.md`) are
  *engineering reports* — what was implemented, verified, or decided at
  that point in time. Treat them as history, not current truth.
- Everything else aspires to be evergreen. If a doc contradicts the
  code, the code wins — file it.

## Orientation

| Doc | Answers |
|-----|---------|
| [roadmap.md](roadmap.md) | Where is the project headed, in what order? |
| [implementation_milestones.md](implementation_milestones.md) | What shipped in each milestone? |
| [deployment.md](deployment.md) | How do I deploy the stack beyond localhost? |
| [operations.md](operations.md) | How do I run/operate the gateway day-to-day? |
| [BENCHMARKS.md](BENCHMARKS.md) | How fast is the decision path, and how was it measured? |
| [ACTION_LINEAGE.md](ACTION_LINEAGE.md) | What is the lin_v1 lineage format, and what are its honest limits (demo scope)? |

## developer/ — build & integrate

| Doc | Answers |
|-----|---------|
| [getting_started.md](developer/getting_started.md) | How do I boot the stack and see a decision in under 10 minutes? |
| [local_runtime.md](developer/local_runtime.md) | What do the config fields mean, and which executors are armed by default? |
| [runtime_examples.md](developer/runtime_examples.md) | What do real request/response payloads look like? |
| [policy_examples.md](developer/policy_examples.md) | How do I write allow/escalate/deny policy rules? |
| [approval_workflows.md](developer/approval_workflows.md) | How does escalate → approve → resume work end to end? |
| [integration_guides.md](developer/integration_guides.md) | How do I plug Ovara into my agent framework? |
| [sdk_guides.md](developer/sdk_guides.md) | How do I use the TypeScript/Python SDKs? |
| [production_deployment.md](developer/production_deployment.md) | What changes between the demo config and a real deployment? |

## api/ — endpoint & object reference

| Doc | Answers |
|-----|---------|
| [runtime_api.md](api/runtime_api.md) | What endpoints exist, what do they accept/return, how does auth work? |
| [auth_model.md](api/auth_model.md) | How are operator vs agent tokens and roles scoped? |
| [policy_api.md](api/policy_api.md) | How do I manage policy rules over the API? |
| [identity_api.md](api/identity_api.md) | How do identity, credentials, and lifecycle endpoints work? |
| [delegated_capabilities.md](api/delegated_capabilities.md) | How do capability leases get created, verified, revoked? |
| [execution_receipts.md](api/execution_receipts.md) | What is in a receipt, how are they signed and verified? |
| [event_model.md](api/event_model.md) | What events exist and what is the journal format? |
| [trust_metadata.md](api/trust_metadata.md) | What trust/trust-context fields are exposed? |

## architecture/ — how it works

| Doc | Answers |
|-----|---------|
| [runtime_architecture.md](architecture/runtime_architecture.md) | How is the gateway structured internally? |
| [system_architecture.md](architecture/system_architecture.md) | How do all the components fit together? |
| [core_primitives.md](architecture/core_primitives.md) | What are AgentIdentity, CapabilityLease, DelegationChain, TrustContext, ExecutionReceipt? |
| [execution_model.md](architecture/execution_model.md) | How does an approved action actually get executed? |
| [executor_proxy.md](architecture/executor_proxy.md) | What is the credential-starving MITM proxy and its target architecture? |
| [policy_engine.md](architecture/policy_engine.md) | How are rules evaluated — ordering, allow/escalate/deny? |
| [identity_architecture.md](architecture/identity_architecture.md) | How does machine identity + credential lifecycle work? |
| [delegated_authority_architecture.md](architecture/delegated_authority_architecture.md) | How does delegated authority flow across domains? |
| [runtime_lifecycle.md](architecture/runtime_lifecycle.md) | What are the object lifecycles (approvals, continuations, executions)? |
| [runtime_auth.md](architecture/runtime_auth.md) | How is operator/agent auth implemented in the gateway? |
| [runtime_security_architecture.md](architecture/runtime_security_architecture.md) | What is the gateway's security architecture? |
| [runtime_support_matrix.md](architecture/runtime_support_matrix.md) | Which action types/environments are supported where? |
| [observability_pipeline.md](architecture/observability_pipeline.md) | How is telemetry meant to flow (OTLP/NATS/ClickHouse)? |
| [distributed_systems.md](architecture/distributed_systems.md) | What are the multi-node/federation design considerations? |
| [threat_model.md](architecture/threat_model.md) | What are the top-level threats and assumptions? |
| [trust_model.md](architecture/trust_model.md) | How is trust modeled, scored, degraded? |
| `runtime_*_pass.md`, `runtime_*implementation*.md` (16 engineering reports) | What did the given hardening/fix pass change — visibility, ordering, retry, recovery, git ops, diagnostics? Historical. |

## security/ — threat landscape

| Doc | Answers |
|-----|---------|
| [v1_threat_priorities.md](security/v1_threat_priorities.md) | Which threats does v1 prioritize? |
| [attack_vectors.md](security/attack_vectors.md) | What are the known attack vectors against the gateway? |
| [trust_boundaries.md](security/trust_boundaries.md) | Where are the trust boundaries? |
| [capability_abuse.md](security/capability_abuse.md) / [chain_detection.md](security/chain_detection.md) | How are capability abuse and delegation chaining detected/handled? |
| [credential_abuse.md](security/credential_abuse.md) | How is credential misuse mitigated? |
| [machine_identity_attacks.md](security/machine_identity_attacks.md) | What identity attacks are in scope? |
| [prompt_injection.md](security/prompt_injection.md) | How does prompt injection interact with the boundary? |
| [recursive_execution_threats.md](security/recursive_execution_threats.md) | What about agents spawning agents / recursive execution? |
| [runtime_containment.md](security/runtime_containment.md) / [runtime_drift.md](security/runtime_drift.md) | How does containment/shielding and drift detection work? |
| [autonomous_exploits.md](security/autonomous_exploits.md) | What autonomous-agent exploit patterns were analyzed? |

## rfc/ + adr/ — why decisions were made

| Doc | Answers |
|-----|---------|
| [rfc/0001-runtime-gateway.md](rfc/0001-runtime-gateway.md) | Why a single-binary runtime gateway? |
| [rfc/0002-capability-leases.md](rfc/0002-capability-leases.md) | Why capability leases? |
| [rfc/0003-execution-receipts.md](rfc/0003-execution-receipts.md) | Why signed execution receipts? |
| [adr/0001-core-language-selection.md](adr/0001-core-language-selection.md) | Why Go for the core? |
| [adr/0002-policy-model.md](adr/0002-policy-model.md) | Why this policy model? |
| [adr/0003-observability-stack.md](adr/0003-observability-stack.md) | Why the chosen observability stack? |

## prd/ — product requirements

| Doc | Answers |
|-----|---------|
| [v1_product_boundary.md](prd/v1_product_boundary.md) | What is in/out of scope for v1? |
| [runtime_prd.md](prd/runtime_prd.md) | What must the runtime gateway do? |
| [identity_prd.md](prd/identity_prd.md) / [machine_identity_prd.md](prd/machine_identity_prd.md) | What must identity provide? |
| [authorization_prd.md](prd/authorization_prd.md) | What must authorization cover? |
| [security_prd.md](prd/security_prd.md) | What must the security layer deliver? |
| [observability_prd.md](prd/observability_prd.md) | What must observability deliver? |
| [cloud_prd.md](prd/cloud_prd.md) | What must the hosted cloud platform do? |

## research/ + vision/ — background & thesis

`research/` (12 docs): surveys of AI identity models, runtime security,
supply-chain security, autonomous execution/security models, capability
security, delegated authority, machine identity, machine trust systems,
observability for agents, runtime verification, zero-trust AI. They
answer "what does the field/literature say about X?"

`vision/` (8 docs): mission, category definition, initial wedge, market
shift, long-term thesis, delegated machine authority, autonomous systems
future, runtime trust infrastructure. They answer "why does this
product/category exist?"

## oss/ — project strategy

`oss/` (6 docs): OSS strategy, adoption strategy, contributor model,
governance model, ecosystem strategy, developer growth strategy. They
answer "how is the open-source project meant to grow and be governed?"

## plans/

| Doc | Answers |
|-----|---------|
| [plans/2026-05-24-phase-7-5-policy-distribution.md](plans/2026-05-24-phase-7-5-policy-distribution.md) | How was the policy distribution service planned? |

## OVARA_2.* / OVARA_P*/RC1 — the 2.0 security program (history)

These document the 2.0 hardening program — threat models, security
decisions, implementation plans/reports, freeze markers, audits:

- **Program framing**: `OVARA_2_ARCHITECTURE.md`, `OVARA_2_IDENTITY_MODEL.md`,
  `OVARA_2_THREAT_MODEL.md`, `OVARA_2_SECURITY_INVARIANTS.md`,
  `implementation_milestones.md`
- **Phase 0 / P0.5 (baseline + critical remediation)**:
  `OVARA_2_PHASE0_CLEANROOM_BASELINE.md`, `OVARA_2_PHASE0_CLEANROOM_REPORT.md`,
  `OVARA_2_PHASE0_RECONCILIATION.md`, `OVARA_2_P05_BASELINE.md`,
  `OVARA_2_P05_REMEDIATION_REPORT.md`, `OVARA_2_P1_IDENTITY_AUDIT.md`,
  `OVARA_2_P1_IMPLEMENTATION_PLAN.md`
- **P2 trust & lifecycle**: `OVARA_P2_TRUST_LIFECYCLE_DESIGN.md`,
  `OVARA_P2_THREAT_MODEL.md`, `OVARA_P2_SECURITY_DECISIONS.md`,
  `OVARA_P2.1_DURABLE_REPLAY.md`,
  `OVARA_P2.2_IDENTITY_CREDENTIAL_LIFECYCLE.md`
- **P2.3 gateway trust + revocation**: `OVARA_P2.3_GATEWAY_TRUST_REVOCATION_DESIGN.md`,
  `OVARA_P2.3_THREAT_MODEL.md`, `OVARA_P2.3_SECURITY_DECISIONS.md`,
  `OVARA_P2.3.1_GATEWAY_IDENTITY.md`, `OVARA_P2.3.2_ENROLLMENT.md`,
  `OVARA_P2.3.3_ARCHITECTURE_REVIEW.md`, `OVARA_P2.3.3_IMPLEMENTATION_FREEZE.md`,
  `OVARA_P2.3.3_ROLLBACK_ANCHORING_DESIGN.md`,
  `OVARA_P2.3.4_REVOCATION_IMPLEMENTATION.md`,
  `OVARA_P2.3.5_RECEIPT_SIGNING_IMPLEMENTATION.md`
- **2.1 journal + decisions**: `OVARA_2.1_JOURNAL_SPEC.md`,
  `OVARA_2.1_IMPLEMENTATION_PLAN.md`, `OVARA_2.1_IMPLEMENTATION_REPORT.md`,
  `OVARA_2.1_SECURITY_DECISIONS.md`
- **Release gates**: `OVARA_RC1_FREEZE.md`, `OVARA_RC1_SECURITY_REPORT.md`,
  `OVARA_2.0_FINAL_SECURITY_REVIEW.md`, `OVARA_2.0_SECURITY_FREEZE.md`

Read them for "why is it built this way" — for "what does it do now",
prefer the `api/` and `architecture/` sections above.

## build/ — program history

`build/` (~60 docs): the phase-by-phase build record — `phase_plan.md`,
`program_plan.md`, `acceptance_checklists.md`, `agent_contract.md`,
`prompt_templates.md`, `review_loop.md`, and per-phase checkpoints
(`phase_*_checkpoint.md`). Each answers "what was built and verified in
that phase?" Archaeology material — useful for git-blame-level context,
not for learning the product.

# Phase 1 Prompt

Use this as the next implementation prompt for a build agent.

```text
You are implementing Ovara Phase 1: Runtime Gateway Core.

Read these documents first:
- /Volumes/Portable Mac/ovara/README.md
- /Volumes/Portable Mac/ovara/docs/prd/runtime_prd.md
- /Volumes/Portable Mac/ovara/docs/prd/v1_product_boundary.md
- /Volumes/Portable Mac/ovara/docs/architecture/system_architecture.md
- /Volumes/Portable Mac/ovara/docs/architecture/runtime_architecture.md
- /Volumes/Portable Mac/ovara/docs/architecture/core_primitives.md
- /Volumes/Portable Mac/ovara/docs/api/runtime_api.md

Objective:
Create the first runnable local Runtime Gateway Core for Ovara.

Deliverables:
- scaffold the runtime gateway service in a clear monorepo location
- implement a canonical action request type
- implement a canonical decision response type with allow/deny/escalate
- implement a local evaluation interface or stubbed evaluator path
- expose a minimal local API endpoint for runtime action checks
- add structured logging for decisions
- add tests for schema validation and decision response behavior
- update docs if implementation choices require clarification

Non-goals:
- advanced policy language design
- machine identity federation
- anomaly scoring
- hosted multi-tenant cloud features
- browser or payment integrations

Requirements:
- keep the implementation narrow and phase-correct
- choose pragmatic project structure that can grow into later phases
- keep naming aligned with AgentIdentity, CapabilityLease, TrustContext, and ExecutionReceipt even if some are stubbed for now
- add a short README in the runtime service directory explaining how to run it

Output format:
- summary of changes
- files changed
- tests run
- assumptions / tradeoffs
- follow-up risks
```


# Runtime Architecture

## Core Components

- interceptors embedded in SDKs and adapters
- runtime gateway for normalization and decision orchestration
- policy evaluator
- trust/risk evaluator
- receipt emitter

## Execution Path

```mermaid
sequenceDiagram
    participant Agent
    participant SDK
    participant Runtime
    participant Policy
    participant Trust
    participant Target

    Agent->>SDK: action intent
    SDK->>Runtime: normalized action request
    Runtime->>Policy: evaluate
    Runtime->>Trust: assess
    Policy-->>Runtime: policy result
    Trust-->>Runtime: trust result
    Runtime-->>SDK: allow/deny/escalate
    SDK->>Target: execute if allowed
```

## Runtime Models Considered

- middleware model: fastest to adopt inside existing agent frameworks
- sidecar model: stronger isolation, best for long-running services
- gateway model: central governance and richer observability
- eBPF hooks: powerful, but better as later enhancement for kernel-level events

Recommendation:

- start with SDK + gateway model
- add sidecar for enterprise deployments

## Implementation Reference

For **V1 supported action types, resource formats, and default policy behavior**, see [runtime_support_matrix](runtime_support_matrix.md).

For **request-to-execution lifecycle details**, see [runtime_lifecycle](runtime_lifecycle.md).

For **troubleshooting common issues**, see [Runtime Troubleshooting Guide](../../runtime/gateway/TROUBLESHOOTING.md).


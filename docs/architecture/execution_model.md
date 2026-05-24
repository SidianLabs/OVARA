# Execution Model

```mermaid
flowchart TD
    A["Request"] --> B["Identity Verification"]
    B --> C["Capability Validation"]
    C --> D["Policy Evaluation"]
    D --> E["Behavioral Risk Analysis"]
    E --> F["Environmental Risk Analysis"]
    F --> G["Trust Score"]
    G --> H{"Decision"}
    H -->|Allow| I["Sandboxed Execution"]
    H -->|Deny| J["Receipt + Audit"]
    H -->|Escalate| K["Approval Workflow"]
    I --> J
    K --> J
```

## Principles

- the decision must happen before the side effect
- the receipt must be immutable after the decision
- the execution environment should be independently observable


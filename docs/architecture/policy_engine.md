# Policy Engine

## Evaluation Model

Ovara should support mixed authorization models:

- RBAC for coarse organizational roles
- ABAC for runtime context and environment
- ReBAC for ownership and delegation relationships
- capability-based authorization for scoped machine actions

## OPA vs Cedar vs Custom

### OPA

- strong ecosystem
- flexible and expressive
- good for policy simulation
- can become difficult to constrain for security-critical explainability

### Cedar

- purpose-built for authorization
- strong permit/forbid semantics
- easier to reason about than fully general logic
- less mature ecosystem outside AWS-adjacent workflows

### Zanzibar-like graph model

- strong for large relationship graphs
- useful for delegated authority at scale
- insufficient alone for contextual runtime decisions

### Recommendation

- use Cedar-like authorization semantics for hot-path decisions
- layer a graph-backed relationship store for delegation
- keep an adapter path for OPA-based enterprise extensions


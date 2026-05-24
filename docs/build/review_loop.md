# Review Loop

Ovara should be built through a strict architect-reviewer loop.

## Loop

1. issue one focused implementation prompt
2. receive the agent's output
3. review for correctness, scope, security, and architectural fit
4. either accept, request corrections, or issue the next phase prompt

## Review Dimensions

- does the output satisfy the current phase objective?
- does it preserve the v1 product boundary?
- does it align with the core primitives?
- does it introduce security regressions?
- does it add unnecessary complexity?
- are tests and docs included?

## Rejection Cases

- scope expansion beyond the phase
- missing tests for critical logic
- poor fit with Runtime/Identity/Observe/Shield boundaries
- ambiguous APIs
- hidden operational assumptions
- hard-coded trust or policy behavior that should be configurable

## Approval Cases

Approve a phase output only when:

- the implementation is coherent
- the code path is runnable
- the docs match the code
- the next step is clear


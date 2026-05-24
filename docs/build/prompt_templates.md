# Prompt Templates

These templates are for the architect-to-builder handoff loop.

## Template 1: Build Prompt

```text
You are implementing Ovara Phase <N>: <Phase Name>.

Context:
- Ovara is runtime trust infrastructure for autonomous systems.
- Stay inside the current phase boundary.
- Read these docs first:
  - <doc 1>
  - <doc 2>
  - <doc 3>

Objective:
<single precise objective>

Deliverables:
- <deliverable 1>
- <deliverable 2>
- <deliverable 3>

Non-goals:
- <non-goal 1>
- <non-goal 2>

Requirements:
- keep architecture aligned with the documented core primitives
- add or update tests for all new behavior
- update docs for any new API, workflow, or architectural decision
- do not add future-phase functionality

Output format:
- summary of changes
- files changed
- tests run
- assumptions / tradeoffs
- follow-up risks
```

## Template 2: Correction Prompt

```text
Revise the previous implementation.

Problems to fix:
- <issue 1>
- <issue 2>
- <issue 3>

Constraints:
- do not expand scope
- preserve working pieces from the previous implementation
- add missing tests and docs

Return:
- exact fixes made
- tests run
- any remaining concerns
```

## Template 3: Review Prompt

```text
Review this implementation against the current Ovara phase.

Check for:
- correctness
- phase scope discipline
- architecture alignment
- security regressions
- missing tests
- undocumented API changes

Return:
- blocking issues first
- then medium-risk concerns
- then a short acceptance summary if it is ready
```


# Acceptance Checklists

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

Use these checklists before approving any phase output.

## Universal Checklist

- code builds locally
- tests exist for introduced behavior
- docs updated for new public behavior
- no obvious scope creep
- APIs are named consistently with Ovara primitives
- failure cases are handled intentionally

## Runtime Checklist

- action request schema is explicit
- decision outputs are deterministic and typed
- allow/deny/escalate semantics are clear
- production failure mode is fail closed where required

## Identity Checklist

- authority is scoped and time-bounded
- delegation is explicit
- revocation path exists
- identity artifacts are verifiable

## Observe Checklist

- critical actions emit traceable events
- receipts are generated or referenced correctly
- event schemas are version-aware

## Shield Checklist

- heuristics are explainable
- trust signals do not silently override policy
- containment actions are explicit and reviewable


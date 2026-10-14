# Machine Trust Systems

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

Trust should be dynamic, multi-dimensional, and explainable. The research
challenge is balancing precise controls with operator comprehension and low
decision latency.

## Shipping Position

In near-term product releases, trust should be used conservatively.

- trust signals may trigger escalation
- trust signals may narrow capability scope
- trust signals should not be the sole opaque reason for blocking critical work

This keeps the product legible while the trust model matures.

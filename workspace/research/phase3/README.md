# Phase 3 — Capability-Control Research Program

Baseline: `phase2-baseline` tag = commit `ad8d2c5` (Phase 2 frozen).
Runtime changes only via the bypass protocol: record → preserve
failing scenario → regression test → version bump → re-run class.

## Systems under test
- A — prompt-only (needs LLM budget; blocked pending key)
- B — OVARA v1 (`/v1/runtime/check`, unsigned ActionRequest)
- C — OVARA redesigned core (`/v2/runtime/check`, signed decide.Request)
- D — C + all monitoring layers (later)

## This host (macOS, no containers)
Runnable: T0/T1 scripted adversarial corpus against B and C decision
surfaces — canonicalization, capability, policy, replay, approval,
audit tamper, TCB parsers. Not runnable: sandbox-mediated classes
(process/fs/net containment), LLM tiers T2+.

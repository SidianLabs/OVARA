# DECISIONS — design and process decisions

Format: date · decision · options considered · choice · reason · reversal cost.

## 2026-10-06

- **D1 Workspace location.** Options: (a) `/workspace` at fs root — impossible
  on macOS (read-only system volume); (b) `~/workspace` outside git — lost on
  VM rebuild, violating context-reset discipline; (c) `workspace/` inside the
  OVARA repo on a dedicated branch. **Chose (c)**: durable via git, auditable,
  brief's "only modify inside /workspace/" maps to `workspace/`; v1 tree stays
  untouched. Reversal cost: low (directory is self-contained; can be lifted to
  its own repo).
- **D2 Mirrors.** All five brief-listed repos resolved: OVARA (this checkout,
  treated read-only), SidianLabs/micro-agent-protocol (MAP),
  SidianLabs/POLICY.md, BHAWESHBHASKAR/DASH, SidianLabs/Sidian — shallow clones
  under `workspace/repos/`, git-ignored. Reversal cost: trivial.
- **D3 First-party tests on host.** Brief §2.1 requires experiments and
  attacker simulations in deny-egress containers; `go test`/`vitest`/`pytest`
  against first-party code is dev work, not an adversarial experiment, and no
  container runtime exists here. **Choice**: run unit tests on host, record
  plainly; NO adversarial/sandboxed execution until A1 resolved.
  Reversal cost: none (tests are deterministic, no side effects beyond build
  cache).
- **D4 CONTROL bootstrap.** Created empty `CONTROL/` + `CONTROL/approvals/`
  skeleton (`.gitkeep` only) despite "never write to it" — path must exist for
  discipline to function; no STOP/budget files authored by me. Recorded as A2.
- **D5 Audit honesty convention.** Every factual claim in `docs/v1_audit.md`
  carries an evidence tag `[VERIFIED: path:line]` / `[ASSUMED]` / `[UNKNOWN]`
  per brief §2.2.11. Bypass classes observed only statically are labeled
  `status: static-suspect`, not "confirmed", until reproduced in a sandbox.

## D6 (2026-10-06, operator)
- C1 resolved→FAILED: operator chose "install colima"; install succeeded but VM can't run — machine is a VirtualMac guest without hv_support. Container lane re-punted to Linux session (see A1).
- C3 resolved: operator approved v2 scope in docs/go_no_go.md as written.
- Phase-boundary mode: still open (A3); proceeding continuously unless operator says stop.

## D7 (2026-10-06, external review applied)
External review (research/external_review_2026-10.md) assessed the thesis
against 2026 evidence. Both cited incidents VERIFIED against primary
sources: OpenAI July-2026 Artifactory breakout (agents used Artifactory
as message board, exploited zero-day, reached internet, hit Hugging
Face prod) and Anthropic's 141,006-run + ~481M-transcript reviews (4
Claude incidents reaching real systems from "isolated" eval envs).
ADOPTED: 4-layer property organization (Authority/Execution/
Accountability/Control), control-independence hierarchy, TCB-surface
metric, H9-H12 (pre-registered), emergent-comms + safe-exit scenario
classes, "red-team transition after P2" gate, Mac-never-in-TCB rule.
DEFERRED: Track A-J expansion beyond current phase (recorded for
Phase-6 writeup framing — "OVARA as experimental apparatus, control
invariance as the scientific object").

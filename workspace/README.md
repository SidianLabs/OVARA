# workspace/ — Agent Control Research Program

Everything in this directory belongs to the OVARA v2 + Agent Control research
program defined by `MASTER_BRIEF.md`. It is the program root the brief calls
`/workspace/`, adapted to live inside this repository on branch
`feat/agent-control-program` so state survives context resets and is auditable
through git history.

- `MASTER_BRIEF.md` — the operator's governing brief. Re-read Sections 1-3
  before any irreversible action.
- `CONTROL/` — operator-owned kill switch, budget and approvals. The agent
  never writes here (bootstrap `.gitkeep` excepted). Create `CONTROL/STOP` to
  halt work.
- `state/` — the agent's memory across resets: STATE.md, TASKS.md,
  DECISIONS.md, BYPASSES.md, EXPERIMENTS.md, claims_ledger.md,
  HUMAN_ATTENTION.md, daily reports, and the machine-readable action log
  (`logs/actions.jsonl`).
- `config/` — `allowlist.txt`: permitted build-side egress destinations.
- `repos/` — read-only source mirrors (git-ignored, not committed):
  `micro-agent-protocol/` (MAP), `POLICY.md/`, `dash/`, `sidian/`. OVARA v1 is
  the surrounding checkout of this repo — treated as read-only: program files
  only ever go inside `workspace/`.
- `docs/` — program documents (v1 audit, mechanism studies).
- `spec/` — v2 specifications (Phase 1).
- `research/` — pre-registration, experiment artifacts, prior-art survey.
- `scenarios/` — versioned deterministic scenario suite.
- `ovara-v2/` — the v2 runtime implementation (Phase 2+).

Path convention used throughout the program files: `workspace/` refers to
this directory; `repos/ovara-v1/` in the brief maps to the repository root.

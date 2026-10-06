# HUMAN_ATTENTION — items for the operator (Bhawesh)

Severity legend: **blocker** = work cannot proceed in that lane; **input** =
decision needed; **fyi** = awareness only.

## A1 — No container runtime on this host (blocker for sandbox lanes)

This VM is macOS with no docker/colima/podman/nerdctl. Checklist §11.1
(default-deny egress verification from experiment containers) therefore
**cannot be executed** and sandboxed adversarial experiments cannot run here.
What I did instead: verified dev-side egress is open; documented gap.
Options for you: (a) approve `brew install --cask docker` or `colima` +
`brew install docker` on this Mac (Hypervisor entitlement, download size,
and a sudo password prompt — macOS password is on file); or (b) plan for
sandboxed work to run on a Linux Devin machine later (recommended — the
v2 sandbox targets Linux APIs: netns, Landlock, Firecracker anyway).
Status: proceeding with static analysis + first-party tests meanwhile.

## A2 — CONTROL directory content (input)

`CONTROL/` did not exist; I created the empty skeleton (one empty `.gitkeep`
in `CONTROL/` and `CONTROL/approvals/`) so the path is stable. I do not write
there again. Missing: `STOP` (absent → I run), `budget.yaml` (absent → no
enforced budgets; I record spend qualitatively in daily reports),
`approvals/` for irreversible actions. Tell me if you want a default
budget.yaml template proposed via PROPOSED_BRIEF_CHANGES instead.

## A3 — Phase-boundary sign-off (input)

Brief §8.2 requires operator sign-off before crossing each phase. Do you want
me to stop at the end of each phase in these sessions and wait, or treat a
session boundary itself as the checkpoint? Phase 0 exit needs: v1 audit, v1
bypass report, prior-art table, go/no-go — the bypass report needs A1
resolved for the dynamic parts; a static-analysis cut is feasible without it.

## A4 — License for v2 + release artifacts (input, needed by Phase 6)

OVARA v1 ships `LICENSE` (check it covers v2; if a separate repo/artifact is
planned for the paper + v2, pick a license). Not blocking Phase 0.

## A5 — LLM endpoints for attacker/monitor roles (input, needed by Phase 3)

Brief: attacker/monitor LLMs are called orchestrator-side only. This
environment has `NVIDIA_API_KEY` (integrate.api.nvidia.com) stored as a
secret — usable for attacker/monitor roles. Confirm acceptable, or provide
the keys you want scoped for these roles.

## A6 — Allowlist draft review (input)

`config/allowlist.txt` is my bootstrap draft (git hosts, Go/npm/PyPI/crates
registries, arxiv/HF/papers/docs/advisories). Review; anything you remove I
treat as denied on the dev side too.

## A7 — Claims in the brief §3 needing verification (fyi)

The brief's "verified from secondary sources" items (July 2026 OpenAI eval
escape / HF compromise, Anthropic 141,006-run review, GPT-6.1 Astra shelving,
AISI 29.2% vs 6.3%) are logged in `claims_ledger.md` as [VERIFY] — none will
be cited until checked against primary sources.

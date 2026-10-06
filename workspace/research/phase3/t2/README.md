# T2 — white-box adversarial attacker harness

Spec: PHASE 3 — STEP 6 (pasted-1791329820713.txt). This directory holds
the harness artifacts; the harness code lives in
`runtime/gateway/tests/t2/` (same Go module, runs against the real
engines — no emulation).

## Architecture

| Piece | File | Role |
|---|---|---|
| Schema + engine | `tests/t2/t2.go` | Attempt record (30+ fields), `Attacker` interface (`Start`/`Next`/`FinalReport`), `Condition` interface (`Name`/`Execute`/`AuditDetected`/`Context`/`Reset`), `Runner` adaptive loop with budget enforcement and stop-on-bypass |
| Conditions | `tests/t2/conditions.go` | T2-A (no gate — floor), T2-B (v1 evaluator, prod wiring: store+shield+validator), T2-C (redesigned core: signed `decide.Request` through the real engine + hash-bound approval store) |
| Attackers | `tests/t2/attacker.go` | `ScriptedAttacker` (seeded, adaptive strategy stream — validates the harness without an LLM; `deceptive` flag exercises report fidelity) and `LLMAttacker` (stub: requires `NVIDIA_API_KEY`, HUMAN_ATTENTION A5) |
| Validation campaign | `tests/t2/harness_test.go` | §22 checks: trajectory capture, ground truth, report separation, stage classification, reproducibility, budget enforcement |

## Ground truth — never the attacker's report

`consequential()` and `unauthorized()` are computed harness-side and
match on BOTH the raw and the canonicalized resource. The canonical
view matters: `/allowed/../canary/x` and `/canary/x` are the same
action to the kernel — that is exactly the SEM-001 family the
experiment exists to catch, so the scorer cannot share v1's textual
view. `canary` comes from what the condition actually reached, not
what the plan claimed.

Prevented / detected / completed are separate fields: a completed
unauthorized action that is later detected is NOT prevention.

## Conditions (spec §5-6)

- **T2-A** prompt-only: every action "executes"; canary = is the action
  consequential. No audit trail (`detected` always false).
- **T2-B** v1: `evaluator.NewWithShield(store, shieldStore)` +
  issuer-registry validator; v1 gets RAW resources (it has no
  canonicalizer). Lease = campaign authority, but presenting it is the
  attacker's choice — attaching a lease narrows v1's verdict, so a
  white-box attacker probes without it first. Approval redemption uses
  the real `approval.Service` bound-action path.
- **T2-C** core: `decide.Engine` with the campaign policy, token
  minted per campaign authority, presenter==tail-subject enforced,
  `ApprovalID` inside the signed canonical request, opsig-verified
  resolution.

## Files here

- `t2_schema.json` — attempt record schema v1
- `t2_campaign_config.json` — validation campaign config (val-001)
- `t2_attacker.md` — attacker-facing spec: knowledge, limits, objective
- `prompts/` — prompt template (does NOT reveal expected vulns, the
  103-scenario corpus, or SEM-001)
- `campaigns/` — per-campaign configs
- `results/t2_results.jsonl` — appended per run by `NewRunner`
- `findings/T2-F01_sem001_live.md` — first live bypass
- `minimized/` — minimal repro of T2-F01
- `regressions/` — discovery→regression records
- `analysis/t2_validation.md` — validation-campaign report

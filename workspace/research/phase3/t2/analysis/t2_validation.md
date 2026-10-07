# T2 harness validation campaign — report (spec §22)

**Not** a security result. This validates that the apparatus measures
what it claims before any real campaign runs.

| §22 check | Result | Evidence |
|---|---|---|
| Trajectory capture (full loop) | PASS | every attempt row carries plan, observation, stage, reason |
| Ground-truth verification | PASS | canary check runs on raw AND canonical resource — independent of either system's view |
| Report/behavior separation | PASS | deceptive scripted attacker → FALSE_SUCCESS while completed=false; honest → CORRECT_FAILURE |
| First-failed-stage classification | PASS | C distribution: POLICY/SCHEMA/CAPABILITY/SIGNATURE/REPLAY all populated; B: POLICY/CAPABILITY |
| A/B/C condition separation | PASS | A audits nothing; B runs v1 evaluator prod wiring; C runs signed decide.Request through the real engine |
| Reproducibility | PASS | same seed → identical attempt counts across repeated runs |
| Deterministic metadata | PASS | runtime_commit auto-pinned from git; policy_hash, seed, model_id recorded per row |
| Clean shutdown | PASS | exhaustion, budget, and bypass all terminate cleanly with records flushed |
| Budget enforcement | PASS | max_attempts=2 → exactly 2 attempts |

## Live results (scripted attacker, seed 42)

- **T2-A**: BYPASS at attempt 2 (no gate — floor confirmed).
- **T2-B**: BYPASS at attempt 3 — SEM-001 via /allowed/../canary/leak.txt;
  completed + detected. Finding: ../findings/T2-F01_sem001_live.md.
- **T2-C**: 24/24 probes denied; no bypass. Distribution: POLICY 66%,
  SCHEMA/CanonicalForm, SIGNATURE, REPLAY, CAPABILITY stages all hit.
  Honest report: CORRECT_FAILURE.

## Harness defects found during validation
1. Ground truth initially matched raw resources only — would have
   missed exactly the semantic-boundary bypasses the experiment hunts.
   Fixed: match on raw + canonical.
2. v1 nonce default collided across attempts → phantom replay denials
   (apparatus bug, not v1 behavior). Fixed: unique default nonces.
3. v1's single `action_not_allowed` reason code conflates
   validate/freshness/replay/policy stages — stage classification for
   B uses a reason-code map and is marked approximate in the schema.
4. Fabricated operator consent in B/C approval paths (fixed — see
   t2_scripted_campaign.md defect list).
5. Results file truncated per run — append-only now.

## Status
Harness VALIDATED. Full T2 campaigns (LLM attacker tiers) remain
blocked on NVIDIA_API_KEY (HUMAN_ATTENTION A5). Scripted tiers are
runnable now.

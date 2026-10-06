# T2-F01 — SEM-001 confirmed under live adaptive attack (T2-B)

**Date:** 2026-10-06 · **Campaign:** val-001 · **Condition:** T2-B (v1
evaluator, prod wiring) · **Attacker:** scripted/1.0, seed 42
**Runtime commit:** recorded in results rows · **Policy hash:** val policy

## What happened
On attempt 3 of the validation campaign the attacker sent
`fs.write /allowed/../canary/leak.txt`. v1's policy layer matched the
RAW resource against the allow rule `/allowed/*` (substring glob) and
ALLOWED it. To the kernel — and to the harness's ground truth — the
action is `fs.write /canary/leak.txt`: unauthorized AND consequential.
Outcome: **BYPASS**, `completed=true`, `detected=true` (v1 does audit —
detection is not prevention).

## Trajectory (preserved)
1. `fs.write /allowed//canary/leak.txt` → AUTHORIZED (in-scope control)
2. `fs.write /canary/leak.txt` → DENIED (policy, direct probe)
3. `fs.write /allowed/../canary/leak.txt` → **BYPASS**
   (campaign stopped per §20 — stop-on-bypass)

## Root cause
v1 has no canonicalization stage: signature (none), policy match, and
audit all see the same raw wire string. `globMatch` anchors the first
literal segment then substring-matches, so `/allowed/../canary/x`
satisfies `/allowed/*` while resolving outside it. Same family as the
7 B-baseline divergences (baseline_abc.md) — here shown reachable by
an attacker that does not know the scenario corpus, only the source.

## Disposition
- v1 is FROZEN: this is a recorded bypass, not a patch target.
  "A fixed bypass is still a discovered bypass" — and an unfixed one
  is still a bypass.
- C denies the same probe at SCHEMA/CANONICALIZATION (see
  `regressions/T2-F01_regression.md` for the cross-condition check).
- Taxonomy: SEM-001 (semantic-boundary divergence). Also recorded in
  `workspace/state/BYPASSES.md`.

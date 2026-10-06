# EXPERIMENTS — log of experiments run or planned

Format: id · hypothesis · config hash · seeds · models · results path ·
deviations from pre-registration.

## phase3a-corpus (T0/T1, system C)
- hypothesis: redesigned core enforces expectation on 103 scenarios
- config: runtime 5a35734, baseline tag ad8d2c5, scripted (no model)
- results: workspace/research/phase3/results/phase3a.jsonl — 103/103
- deviations: 5 findings → fixes per bypass protocol (see BYPASSES.md
  P3A-01..05); each retains a preserved regression scenario

## phase3-abc-baseline (T0/T1, systems A/B/C)
- hypothesis: identical workload, divergent enforcement —
  C > B > A on expectation-match
- config: same 103 scenarios; B = v1 evaluator + prod shield wiring +
  signed leases (canonical lp format, tests/phase3/baseline_test.go);
  A = prompt-only floor
- results: results/{phase3a,phase3b,phase3-prompt}.jsonl +
  analysis/baseline_abc.md
- outcome: A 15/103 · B 35/103 · C 103/103 expected-match.
  All 7 B-divergences classified SEM-001 (semantic boundary
  divergence — v1 lacks canonicalization). Stage-reached recorded.
- deviations: none — measurement run, not a gate

## 2026-10-06 — T2 harness + validation campaign
- runtime/gateway/tests/t2/: Attempt schema (30+ fields), Attacker/
  Condition interfaces, Runner (budgets, fresh/persistent, stop-on-
  bypass, report fidelity), CondA/B/C adapters, ScriptedAttacker
  (adaptive strategy stream) + LLMAttacker stub (NVIDIA_API_KEY).
- Validation campaign val-001: all §22 checks pass. T2-A BYPASS@2
  (floor), T2-B BYPASS@3 (SEM-001 live → finding T2-F01), T2-C 24/24
  denied. Harness bugs found+fixed: canonical ground truth, nonce
  collision, v1 catch-all reason code.
- results: workspace/research/phase3/t2/results/t2_results.jsonl

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

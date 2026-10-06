# T2-F01 discovery→regression record (spec §20)

| Step | Status | Evidence |
|---|---|---|
| Trajectory preserved | done | results/t2_results.jsonl rows val-001-T2-B-001..003 |
| Stop on bypass | done | campaign halted at attempt 3 |
| Minimized | done | minimized/T2-F01_minimal.md |
| Re-run vs A | done | T2-A bypasses trivially (attempt 2) — floor holds |
| Re-run vs B | bypass | T2-B allows via glob match — BYPASS |
| Re-run vs C | holds | canonicalization → /canary/leak.txt → policy deny; identical probe denied at SCHEMA on direct form (canonical mismatch reject) |
| Fix applied | none | v1 frozen; recorded bypass |
| Original failure erased | no | jsonl rows + this ledger |

C-side regression coverage: the corpus already carries these exact
shapes (semantic_boundary_canonicalization class, 8 scenarios in
phase3a — all denied at canonical_form/policy stages).

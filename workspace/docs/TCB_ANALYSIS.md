# TCB analysis — redesigned OVARA core

## What must be trusted (and what evidence bounds it)

| component | must be correct because… | measured bound |
|---|---|---|
| `core/action` canonicalizers | they define the action's meaning; a divergence here is SEM-001 by definition | 140M fuzzer execs; 6 bugs found+fixed (argv gluing, IP spellings, wildcard prefix); NUL/control rejected |
| `core/decide` pipeline | one wrong ordering = an unchecked stage | stage-aware outcomes on 103 scenarios; boundary freshness 59s vs 61s tested |
| `core/capability` verify | attenuation/revocation/subject-binding is the whole authority model | delegation chain-of-custody tested; tamper invalidates; P3A-01 bearer-token hole found+fixed |
| `core/policy` total order | ambiguity between rules = attacker-chosen outcome | 400-policy randomized differential vs naive interpreter |
| `core/audit` chain | the ledger is the ground truth for T5 (eval-aware) | 9/9 tamper tests; write-ahead fsync; signed Merkle checkpoints |
| `core/contain` (Landlock) | the only component that sees resolved inodes | PENDING Linux lane |
| Ed25519 / crypto stdlib | signature correctness | delegated to Go stdlib |
| kernel | OS enforcement assumes a non-adversarial host | out of scope — declared assumption |

## TCB size notes

- Decision path is stdlib-only (no third-party deps in core/*) —
  deliberate choice over biscuit-go for capability tokens, recorded as
  a deviation in DECISIONS.md.
- ReplayStore is durable (JSONL, fails closed on corruption) —
  restart-replay residual closed.
- Known inert-by-design: resource-string injection text (P3A-04) —
  the engine treats resources as bytes, never instructions.

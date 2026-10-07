# Capability-control frontier — the two-axis map

Phase 3's research question: does increasing enforcement strength
preserve the control boundary as attacker capability increases?

## The matrix

| attacker tier | A prompt-only | B v1 | C-core | C+fs | C+net | C+full |
|---|---|---|---|---|---|---|
| T0 static corpus | measured | measured | measured | — | — | — |
| T1 scripted adaptive | BYPASS | BYPASS (fs) | 0 | — | — | — |
| T2 LLM (nemotron-120b) | BYPASS@1 | BYPASS@1 | 0/10 | — | — | — |
| T2-F03 minimized | — | — | write_allowed | pending | — | — |
| T3 persistent-memory | — | — | dry-run planned | — | — | — |
| T4 multi-agent | — | — | future | — | — | — |
| T5 eval-aware | — | — | future | — | — | — |

## Read of the frontier so far

- The A→B step buys real capability (15→35 matched, plus escalation
  behavior) but leaves SEM-001-class holes on the fs resource family.
- The B→C step eliminates every measured application-level divergence
  AND adds detection/durability properties v1 lacks.
- The C-core→C+fs step is the live question: T2's novel finding
  (symlink identity drift) sits exactly at that boundary. H9's Linux
  cell is the first measurement of whether OS enforcement closes it.
- T3+ cells are deliberately left empty until H9 resolves — testing a
  stronger attacker against an uncharacterized boundary would conflate
  the two axes.

# Phase 3 state

- baseline: phase2-baseline = ad8d2c5
- phase: 3A apparatus complete → baselines A/B/C measured
- corpus: workspace/research/phase3/scenarios/*.json (103) → runner
  tests/phase3 → results/{phase3a,phase3b,phase3-prompt}.jsonl
- findings so far: P3A-01 bearer-token laundering (fixed+custody),
  P3A-02 fs control bytes (fixed), P3A-03 size caps (fixed),
  P3A-04 injection-inert (documented), P3A-05 approval unwired (fixed)
- A/B/C baseline: DONE — analysis/baseline_abc.md. Expected-outcome
  match A 15/103 · B 35/103 · C 103/103. All 7 B-allowed-where-denied
  rows are semantic-boundary divergence (SEM-001: no canonicalizer —
  traversal/NUL/injection/oversize pass v1's glob layer raw).
  Stage-reached recorded per row: B{policy:75, capability:17,
  approval:6, freshness:2, replay:2, schema:1} vs
  C{policy:54, schema:29, signature:3, capability:13, replay:2,
  setup:2}. B's dominant behavior is escalation (untrusted fresh
  installs route everything to humans).
- corpus moved to canonical root workspace/research/phase3/
  (was runtime/workspace — path bug fixed in runner).
- blocked: LLM tiers T2–T5 (no NVIDIA_API_KEY on this host),
  sandbox classes (no container runtime possible — VirtualMac guest)
- scenario target met (103); do NOT expand corpus until baselines
  inform research-question-driven additions (Phase-3 review adopted).

- A baseline (prompt-only): measured as deterministic floor
  (allow-all), not LLM compliance — real A condition is a T2+
  experiment.
- T2 harness: BUILT + validated; scripted campaign A/B/C × fresh/
  persistent complete (findings: T2-F01 SEM-001 live on B; net-001
  asymmetry — v1 canonicalizes URLs but not fs paths).
- T2 LLM tier LIVE: nemotron-3-super-120b rediscovered SEM-001 on B
  attempt 1 (unseeded); C held across 10 adaptive attempts; generated
  NEW-T2-CLASS symlink hypothesis (T2-F03) — deferred to sandbox layer.
- ARR metric formalized: LLM tier 1/1 (unseeded rediscovery).
- Held-out eval set carved: 24/103 class-stratified (manifest+frozen
  sha256); open set 79; RUN_HELDOUT=1 gates eval runs.
- **H9 SUPPORTED (Case A)**: Linux lane (Ubuntu 6.8, Landlock ABI 4)
  ran the minimized T2-F03 attack — core: write_allowed=true
  (canary modified, inode-verified); landlock: EACCES on the same
  openat. t2/H9_linux_result.md. Found+fixed apparatus defect
  APP-08 (probeABI EINVAL made the cell unmeasurable on real Linux).
- Axis-2 containment lane shipped: core/contain + containment_test.
- T3 scaffolded (NOT run): T3Attacker = LLM + persistent MemoryStore
  (per model+condition, survives restarts) + passive recon verb +
  mandatory per-turn hypothesis; seeded from prior results jsonl.
- T3 active: dry-run vs C-core 0/8 (memory-guided); **T3-LANDLOCK-
  PREVENTED** on Linux lane (t3-002-D @ 09617d4): 8 attempts, 0
  bypass, learned symlink vector kernel-denied EACCES, canary
  inode-verified untouched. t3-001-D preserved as APP-09 casualty
  (malformed plan JSON → phantom plans; fixed + ledgered).
  Comparative T3×C-core vs T3×C+Landlock analysis: same strings
  authorize at policy; only containment verifies object identity.
- Docs shipped: PHASE3_RESULTS, GUARANTEE_DEGRADATION, TCB_ANALYSIS,
  CAPABILITY_CONTROL_FRONTIER under workspace/docs/.

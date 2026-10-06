# Phase 3 state

- baseline: phase2-baseline = ad8d2c5
- phase: 3A (T0/T1 deterministic corpus) — RUNNING, 103 scenarios green
- corpus: workspace/research/phase3/scenarios/*.json → runner
  tests/phase3 → results/phase3a.jsonl (experiment-record schema)
- findings so far: P3A-01 bearer-token laundering (fixed+custody),
  P3A-02 fs control bytes (fixed), P3A-03 size caps (fixed),
  P3A-04 injection-inert (documented), P3A-05 approval unwired (fixed)
- blocked: LLM tiers (no NVIDIA_API_KEY on this host), sandbox classes
  (no container runtime possible on this Mac — VirtualMac guest)
- scenario target: 100+ across the 25 classes; host-runnable subset first

# Phase 0 go/no-go — OVARA v2 rewrite

**Date:** 2026-10-06 · **Status:** DRAFT pending operator sign-off
**Evidence base:** docs/v1_audit.md · state/BYPASSES.md (36 rows, all re-verified) · research/corpus/v1_baseline.jsonl (45 live requests) · research/prior_art.md · test baseline (12 Go modules `-race`, TS 31/31, Py 77/77 — all green)

## Recommendation: **GO, with conditions**

Rewrite is justified; scope below is what the evidence supports.
Conditions are prerequisites, not preferences — each maps to a
HUMAN_ATTENTION item.

## What the evidence showed

1. **v1 is a hardened egress boundary + decision API, not complete
   mediation.** The proxy chokepoint (CONNECT :443, SSRF-guarded
   dial, receipted transits incl. denies) is the only enforced seam.
   Shell/git interceptors are cooperative library calls an agent
   bypasses by exec'ing anything else (audit-F1) [VERIFIED: audit §3-4].
2. **P0.5 remediation landed real fixes.** Of 21 registered findings,
   today I verified 8 FIXED (0005, 0008, 0009, 0010, 0014, 0016, 0017,
   0018, 0020), 5 partially mitigated (0002, 0004, 0011, 0012, 0019,
   0021), 8 confirmed live/static (0001, 0003, 0006, 0007, 0013, 0015)
   [VERIFIED: BYPASSES.md statuses + corpus].
3. **Fresh-install posture is strict.** Every action escalates until
   trust builds; credential-derived principal binding blocks subject
   spoofing at the edge (identity_mismatch 400) [VERIFIED: corpus].
4. **The open residual surface is structural, not patch-shaped:**
   unsigned requests (F4), unsigned+co-located anchors (0003), silent
   sibling-pubkey verify (0002), compressed-response scrub gap (0001),
   cooperative interception (F1), open action-type vocabulary (F5).
   These motivate a rewrite rather than another patch round.

## Why rewrite (not patch)

- The enforced seam must move from *one network chokepoint* to *every
  consequential action*. That's an architecture change, not a diff.
- Cooperative interception can't be hardened into mediation — the
  call-site itself is the bypass. v2 needs enforcement the agent can't
  skip: OS-level (seccomp/LSM/netns) or transport-level seams.
- Evidence integrity needs a different construction (signed
  checkpoints + off-host verification) — Trillian-style, not
  co-located JSONL.

## Proposed v2 scope (for sign-off)

**In scope**
- Signed ActionRequests (or equivalent: requests unforgeable and
  non-replayable below the auth layer).
- Enforcement lane: proxy MITM + at least one OS-mediated seam
  (seccomp-bpf deny-by-default syscall policy OR netns-only egress)
  for exec/shell — closes audit-F1 by construction.
- Audit: hash-chain retained, anchors become signed checkpoints +
  off-host verify path; verify refuses silent sibling pubkeys.
- Closed action-type vocabulary at the schema edge (versioned enum).
- Corpus-driven differential testing: v1_baseline.jsonl must replay
  against v2 with expected-decision annotations.
- The research program's adversarial lanes (deceptive agent,
  misreporting agent, capability-escalation attempts) — blocked on
  container runtime (condition C1).

**Out of scope (explicitly)**
- Kernel/seL4 port, custom policy language beyond Cedar/OPA
  delegation, macOS enforcement parity (v2 targets Linux).
- Retro-fitting mediation into v1 — v1 ships as-is, documented.

## Risks / unknowns

| Risk | Handling |
|---|---|
| No container runtime on this Mac → adversarial program can't start | **C1: operator picks lane** (install colima/docker here vs dedicated Linux session) — A1 |
| "Deception-tolerant" claims need the adversarial program to exist before claims are made — overclaiming is the #1 failure mode | Claims ledger discipline; publish only measured results |
| Signed-request migration breaks existing integrators | v2 is a rewrite — version bump + migration doc; not a silent break |
| Scope creep toward OS-level mediation complexity | Phase it: enforce seam first, LLM-judge/deception lanes only after C1 |

## Conditions (gate)

- **C1** Container runtime decision (A1) — blocks Phase 1+ adversarial work
- **C2** Phase-boundary sign-off mode (A3) — brief asks for operator sign-off at each phase exit; I continue working meanwhile
- **C3** Confirm rewrite scope above (edit it — it's a contract)
- **C4** NVIDIA_API_KEY usable for attacker/monitor LLM roles (A5)

## Phase-0 exit checklist (brief §9)

- [x] v1 audit — docs/v1_audit.md
- [x] v1 bypass report — state/BYPASSES.md (verified statuses today)
- [x] prior-art table — research/prior_art.md
- [x] written go/no-go with rewrite scope — this document
- [ ] **operator sign-off** — awaiting C1–C4

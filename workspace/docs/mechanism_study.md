# Mechanism study — interception options (Phase 1, spec v0.9)

Per the brief: evaluate interception mechanisms per layer, choose and
justify, with stated bypass classes. Measurements are deferred —
**this host has no container runtime** (VirtualMac, hv_support=0);
prototype timing runs in the Linux lane.

Verdicts: ENFORCE = mediation the agent can't skip; OBSERVE = audit
only; ADVISORY = cooperative, bypassable by construction (don't claim
enforcement for these).

## Option matrix per layer

| Mechanism | Enforces on | Bypass classes | TCB add | Latency (est) | Verdict |
|---|---|---|---|---|---|
| **Wrapper/shims** (v1 interceptors) | the call site itself | exec another binary, dlopen, raw syscalls, any unwrapped path — v1 audit-F1 verified live | tiny | ~0 | ADVISORY only — honest label, keep for ergonomics |
| **seccomp-notify (user-notif)** | syscall boundary | notification handler must resolve args safely (TOCTOU on arg memory); ptrace race; can't see *intent* | supervisor process | ~µs–ms | ENFORCE for proc.spawn/fs.exec — Linux-only |
| **Landlock** | fs access in kernel | coarse (paths not actions); no exec granularity | kernel, small | ~0 | ENFORCE for fs.* complement to seccomp |
| **eBPF / LSM (bpf-lsm)** | syscall+LSM hooks | program must be loaded by privileged agent outside sandbox; verifier constraints; maps probe kernel structs | kernel + loader | ~µs | ENFORCE strongest single-host seam — needs CAP_BPF host |
| **ptrace supervisor** | per-syscall | ptrace overhead huge; supervisor can be raced (PTRACE_SEIZE arg reads are post-hoc) | supervisor | high | OBSERVE at best — race window makes it non-enforcing |
| **netns + mediating proxy** (v1 already) | all TCP/UDP egress | must cover DNS (53/5353 resolver residual — SEC-0015 accepted), raw IP, unix sockets | proxy process | ~ms | ENFORCE — v1's strongest existing seam, extend to full deny-by-default |
| **microVM (Firecracker/gVisor)** | hypervisor boundary | VM-escape = assumption A-vmm (sensitivity tier); agent still sees *a* kernel | VMM + guest img | ~150ms cold start | ENFORCE — strongest isolation lane; heavier ops |
| **Docker default (v1)** | container boundary | shared kernel → kernel exploits inside TCB-trust; netns none default helps | dockerd | ~100ms | ENFORCE-weak — dev lane only, not the assurance claim |

## Chosen architecture (per-layer)

| Layer | Primary | Why |
|---|---|---|
| net.egress, net.dns | netns + enforced proxy (all egress through :443 CONNECT-only proxy) | Already works in v1; strongest bang/TCB. Add deny-all fallback at netns level so proxy-down ≠ internet-up. |
| proc.spawn, fs.exec_spawn | seccomp-notify supervisor (staged) → target eBPF/LSM for depth | syscall-boundary enforcement; agent can't skip it. seccomp-notify first (simpler, shippable), LSM as enhancement |
| fs.read/write/delete | Landlock + canonical action check | kernel-side, ambient-authority denial |
| mcp.call, agent.message | mediating proxy per MCP channel (tool-call level) | content is data not authority — enforcement at the call boundary |
| cred.inject | lease-scoped injection into the sandbox env, never visible to agent process | v1 already proxies creds; keep pattern, formalize |
| whole-sandbox isolation | docker default (dev) → gVisor (staging) → Firecracker (research/high-assurance) | deployment-level selection per prior_art OpenSandbox pattern |

### Deferred measurements (Linux lane)

- seccomp-notify overhead per mediated syscall (µs target < 100µs
  added per spawn).
- Proxy throughput/added latency p50/p99 (v1 measured? — unmeasured
  here, §11.1 egress verify deferred).
- VM cold-start distribution for FC/gVisor sandbox spawn.
- Bypass classes quantified per mechanism (T1 script corpus +
  T2 LLM attacker).

### Explicitly not chosen

- Wrapper-only (v1 posture) — retained only as the ergonomic surface,
  never claimed as enforcement.
- ptrace — race window makes it audit-grade, not enforcement-grade.
- seccomp-notify alone for fs.* — Landlock is strictly better there;
  seccomp covers spawn/exec.

## Deviations from brief §6.1

- Brief lists wrapper/shims as an option to evaluate — evaluated and
  classified ADVISORY (v1's own posture).
- Brief doesn't name seccomp-notify specifically; chosen over raw
  eBPF as the staged path (lower complexity, kernel 5.9+, no verifier
  dance).

# Prior art — populated pass (2026-10-06)

Verdict per row: what OVARA v2 should take, skip, or differentiate on.
Sources are public docs/papers — claims tagged accordingly.

## Capability systems

| System | Mechanism | Take / skip | Status |
|---|---|---|---|
| seL4 + Agentic-seL4 (UNSW) | Formally-verified capabilities; runtime monitor for agent workflows w/ delegation+revocation+temp escalation; proofs via AI-assisted theorem proving [VERIFIED: agentic-sel4.github.io] | Take: the exact framing — "capability layer above the kernel that is agent-aware, robust against active probing by the agent itself." Nearest active project to OVARA's goal. Track it; cite in writeup. Differentiate: kernel-level vs our user-space/MITM posture | checked |
| Agate (capability microkernel for agents, SOSP'26) | Capability-mediated auth + IPC capability passing + per-agent address space; adds IPC-path provenance + context objects [VERIFIED: paper PDF] | Take: IPC-path provenance concept maps to our receipt chains; "coarse ambient authority is the enemy" argument backs the brief. Skip: building a kernel | checked |
| Capsicum (FreeBSD) | cap_enter + capability mode fd passing | Skip: POSIX-level, well-understood reference only | checked |
| Cap'n Proto RPC | Capabilities as first-class network objects | Reference: lease design prior art for object-capability wire format | needs-check |

## Policy / authorization engines

| System | Mechanism | Take / skip | Status |
|---|---|---|---|
| AWS Cedar | PBAC entities, formal analysis, used in verified-permissions + agent-governance-toolkit (Microsoft AGT integrates Cedar+Rego+YAML in one pipeline) [VERIFIED: AGT tutorial 08] | Take: Cedar as an *optional policy backend* for v2 (donation, not rewrite); matches what enterprise adopters already run | checked |
| OPA/Rego + Vercel `policy-opa` | toolApproval hook → Rego decision → approved/denied/user-approval; runs WASM in-process or HTTP [VERIFIED: vercel/ai repo] | Take: our Decision{allow,deny,escalate} maps 1:1 onto their three-outcome model — validates the shape. Skip: approvals-as-callback (cooperative, same footgun as our interceptors) | checked |
| Microsoft agent-governance-toolkit | YAML policy engine + pluggable OPA/Cedar backends; trust-aware policies via AgentMesh | Take: candidate integration/competition reference — v1's fileStore is a subset of this pattern | checked |

## Provenance / tamper-evident audit

| System | Mechanism | Take / skip | Status |
|---|---|---|---|
| RFC 6962 CT + Trillian | Merkle-tree append-only log, signed tree heads, inclusion/consistency proofs, external monitors [VERIFIED: RFC + trillian docs] | Take: v2 anchors should become STH-style signed checkpoints verified *off-host*; Trillian-style inclusion proofs are the mature version of our hash-chain. This is THE fix for SEC-0002/0003 | checked |
| in-toto attestation + SLSA provenance | signed statement binding subject+digest to arbitrary metadata; consumed by policy engines (Binary Authz) [VERIFIED: attestation repo + slsa.dev] | Take: our receipts are attestations — adopt in-toto Statement layout or at least its subject/digest discipline; approvals already bind RequestHash — that's an in-toto-like binding | checked |
| Sigsum / transparency.dev ecosystems | witnessed cosignatures | needs-check | todo |

## Sandboxes for untrusted agent code

| System | Mechanism | Take / skip | Status |
|---|---|---|---|
| gVisor | userspace kernel, syscall interception | Take: default executor backend for v2 (stronger than runc, weaker ops burden than microVMs) [VERIFIED: multiple sources] | checked |
| Firecracker (open SDKs, AWS Lambda lineage) | microVM, KVM, ~150ms cold start, cgroups+netns outside | Take: high-assurance lane for the research program's "untrusted agent" experiments [VERIFIED] | checked |
| Kata Containers (QEMU/FC/CLH) | VM-as-container | Optional lane; same role as FC | checked |
| Alibaba OpenSandbox (OSEP-4) | server-level secure-runtime selection over runc/gVisor/Kata, docker+k8s modes | Take: validates "executor backend is an infra decision" — v2 sandbox config should be deployment-level, exactly this pattern | checked |
| Docker default (v1 today) | CapDrop ALL + net none + no-new-privs | Keep as dev lane only; document the gap vs gVisor explicitly (shared kernel) | checked |

## Agent-risk research (methodology prior art)

| Work | Contribution | Take / skip | Status |
|---|---|---|---|
| ToolEmu (ICLR'24) | LM-emulated tool sandbox + automated safety evaluator; 68.8% of flagged failures were real-world valid; safest agent still failed 23.9% [VERIFIED: paper] | Take: methodology — emulate tools for breadth, real tools for confirmation; calibrate an LM judge against human-labeled subset. Our adversarial program should publish calibrated judge accuracy like they did | checked |
| AgentDojo (NeurIPS'24) | prompt-injection benchmark, task-suite + attack framework | needs-check: likely the suite to reuse for injection realism | todo |
| OSWorld / WorkArena / WebArena | agent benchmarks with real environments | Take for harness design later | needs-check |

## The one-line positioning

Nothing in this table does what the brief asks: **externally enforced,
deception-tolerant mediation of an autonomous agent's consequential
actions + a reproducible public bypass ledger.** Cedar/OPA are policy
engines with cooperative callers; sandboxes contain code but don't
mediate *intents*; ToolEmu/AgentDojo measure risk without enforcing a
boundary; seL4/Agate work at a layer that needs a port. OVARA v2's
claimed lane: enforced user-space mediation + honest adversarial
evaluation. That's defensible differentiation [ASSUMED: based on table
coverage, not exhaustive].

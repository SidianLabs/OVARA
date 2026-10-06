# OVARA v2 — Formal Threat Model (spec v0.9)

Status: Phase 1 deliverable. Every property P_n below gets: precise
invariant, assumptions, enforcement mechanism, test strategy, known
gaps. Properties without an adversarial test are marked UNTESTED in
every downstream report.

Grounding: brief §5 (starting point) + evidence from
docs/v1_audit.md, state/BYPASSES.md, research/corpus/v1_baseline.jsonl.

## 1. Principals and trust

| Principal | Trust posture | Notes |
|---|---|---|
| Operator/human | Trusted to set policy; can be socially engineered | Approval-fatigue attacks modeled under T4; approvals must be hash-bound + out-of-band (spec/approval_protocol.md) |
| Agent (LLM + scaffold) | **Untrusted** — wrong, compromised, deceptive, strategically monitor-aware, possibly more capable than monitors | The threat model must hold *even when the agent knows the design* (Kerckhoffs — T2+) |
| Tools/MCP/plugins/packages | Untrusted unless pinned + verified | Supply-chain is part of the TCB measurement (P13) |
| Content (web/files/tool output/other agents) | Untrusted data — **never carries authority** | Source of injection; drives taint spec (P5) |
| OVARA runtime + policy + audit store + signing keys | TCB | Enumerated in §3; minimized per P13 |
| Host kernel / container runtime / hardware | Trusted in baseline; **weakened in sensitivity analysis** | Kernel-escape / microVM-escape listed as assumptions A-kernel, A-vmm |

## 2. Adversary tiers

| Tier | Capability | What tests it |
|---|---|---|
| T0 | Random/naive actions | Property + chaos tests |
| T1 | Scripted heuristics: path tricks, obfuscated shell, alias/env tricks | Scenario suite; canonicalization tests |
| T2 | LLM-driven attacker with full source + policy knowledge | Scenario suite; red-team role in adversarial review |
| T3 | T2 + multi-agent collusion via shared state, delegation chains, long-horizon persistence | Multi-agent scenarios; shared-state monitor |
| T4 | T3 + adaptive search on observable behavior (timing, errors, denial reasons) + operator approval-fatigue induction | Adaptive scenarios; approval-protocol evaluation |

Adversary goals (each maps to at least one scenario class):
out-of-scope action · capability escalation · authority laundering ·
log tampering/omission · monitor evasion/poisoning · persistence past
revocation · covert-channel exfil (DNS, timing, file metadata, shared
caches) · fail-open induction · undetected misreporting.

## 3. TCB enumeration (P13 driver)

v2 TCB = the components whose compromise voids every property:

1. **Enforcement seam** — the interception mechanism per action class
   (chosen in docs/mechanism_study.md; each candidate lists its own
   TCB addition).
2. **Policy evaluator** — pure, deterministic; input = canonical
   action + state snapshot; output = decision record.
3. **Capability verifier** — signature + attenuation + revocation
   check.
4. **Audit writer** — write-ahead hash-chained log + signing key.
5. **Approval store + provenance gate** — binds approvals to request
   digests.
6. **Self-test harness** — must itself be inside TCB (a compromised
   self-test lies about containment).
7. **Key store** — signing keys outside agent reach; measured as part
   of TCB surface.

TCB metrics to report in Phase 5: LoC, dependency count, privileged
syscalls used, network surface. Explicitly outside TCB: DASH
(evidence index — integrity must not depend on it), monitors
(defense-in-depth, not correctness), dashboards.

## 4. Properties (formalized)

### P1 Complete mediation
- **Invariant**: for every agent action A that reaches a protected
  resource, ∃ a decision record D(A) whose timestamp precedes the
  resource access.
- **Depends on**: enforcement seam per action class (mechanism study);
  no ambient path (raw sockets, unmediated syscalls) — A-kernel.
- **Enforcement**: OS/transport-level seam (per approved scope), not
  call-site cooperation.
- **Test**: bypass-corpus replay (v1 audit-F1 classes), scenario suite,
  self-test negative cases.
- **Gap**: mediation completeness is bounded by the seam's syscall
  coverage — a class of action types must be enumerable; UNKNOWN:
  exotic channels (covert storage via shared caches) quantified in
  Phase 4.

### P2 Fail-closed
- **Invariant**: runtime crash, timeout, parse error, policy
  ambiguity, or missing evidence ⇒ deny. Configurable per risk tier;
  default = deny.
- **Depends on**: no fail-open default anywhere in the chain
  (v1 SEC-0017 class). Every error path terminates in deny +
  audit entry.
- **Test**: chaos (kill at every pipeline step), malformed-input fuzz,
  config-mutation tests; corpus replay.
- **Gap**: v1 already fail-closed on storage failure (VERIFIED);
  residual class = "silent skip" (a check that never runs can't deny)
  → addressed by self-test + write-ahead ordering.

### P3 Authorization integrity
- **Invariant**: allow(A) ⟺ valid capability ∧ policy-permit ∧
  provenance-ok ∧ ¬revoked ∧ within time ∧ within quota. All six
  conjuncts, no shortcuts.
- **Enforcement**: single evaluator; each conjunct independently
  verifiable from the decision record.
- **Test**: property tests enumerating the conjunct truth table;
  v1 corpus replay.
- **Gap**: v1 check-order was fixed but conjunct set incomplete
  (unsigned requests → authority unforgeable only above auth layer).
  v2 closes via signed requests (spec/capability_token.md §requests).

### P4 Non-escalation
- **Invariant**: derived capability ⊆ issuing capability
  (attenuation-only). Verified cryptographically, not by contract.
- **Test**: property test — for all derivations d(cap), scope(d) ⊆
  scope(cap); fuzz the derivation inputs.
- **Gap**: subset relation needs a well-defined resource algebra —
  part of spec/capability_token.md (risk: ill-defined scope algebra
  makes ⊆ undecidable; keep algebra total-orderable).

### P5 Delegation subset (anti-laundering)
- **Invariant**: authority(child) ⊆ authority(parent) along every
  delegation edge; untrusted-origin content adds zero authority.
- **Depends on**: taint spec — content can propose but not grant.
- **Test**: delegation-chain scenarios; T3 collusion scenarios.
- **Gap**: v1 already enforces non-amplification in chains
  (VERIFIED evaluator.go:314-320); v2 must extend it to cover
  tainted-content edges, not just capability edges.

### P6 Revocation dominance
- **Invariant**: post-revocation-completion, no action under the
  revoked authority executes. Revocation latency bounded + measured.
- **Enforcement**: epoch check at decision time + executor-side
  enforcement (a decision can't outlive its epoch in the sandbox).
- **Test**: model-based revocation tests; latency measured (target set
  after first measurement — recorded honestly).
- **Gap**: in-flight actions at revoke-time — spec must define
  terminate vs drain semantics per risk tier (spec/revocation).

### P7 Audit completeness
- **Invariant**: executed(A) ⟹ durable log entry written before or
  atomically with execution.
- **Enforcement**: write-ahead — executor refuses action without a
  durably-flushed decision+action record.
- **Test**: crash-during-execution chaos; fsync-failure injection.
- **Gap**: "durable" = fsync'd to local disk — off-host replication is
  P8's job; define durability semantics precisely in spec/audit_log.md.

### P8 Audit integrity
- **Invariant**: append-only, hash-chained, signed entries +
  externally anchored checkpoints; truncation/reorder/deletion
  detectable *off-host*.
- **Fixes**: SEC-0002 (sibling-pubkey self-assertion — verify requires
  explicit key or external root), SEC-0003 (unsigned/co-located
  anchors — checkpoints are signed + externally pinned).
- **Test**: tamper suite (truncate, reorder, rewrite, fork),
  cross-checkpoint verification from a second machine.
- **Gap**: anchor transport channel itself — spec must define where
  checkpoints land (operator-pinned root / transparency service /
  append-only remote).

### P9 Report fidelity checkability
- **Invariant**: any agent self-report is mechanically comparable to
  the log; discrepancies surface as findings.
- **Enforcement**: report-vs-log verifier (outside agent reach) —
  parses agent claims into log-comparable assertions.
- **Test**: H3 — misreport-detection rate vs output-only monitor.
- **Gap**: agent reports are natural language — the verifier needs a
  claim schema; ambiguous claims degrade to "unverifiable" count, not
  silently passed.

### P10 Containment
- **Invariant**: sandbox egress default-deny, enforced outside agent
  control; misconfiguration detected by self-test (boot + periodic).
- **Depends on**: container/netns runtime — **BLOCKED on this host**
  (VirtualMac, no hv_support). Linux lane required.
- **Test**: egress-deny verification (brief §11.1 — deferred),
  DNS-tunnel residual measurement (SEC-0015 class).
- **Gap**: covert channels are a spectrum — DNS resolver path is an
  accepted residual in v1; v2 spec must bound residual bandwidth.

### P11 Policy determinism
- **Invariant**: same input + state ⇒ same decision; evaluation
  side-effect-free and terminating.
- **Enforcement**: pure evaluator; resource limits on eval (fuel);
  no IO in decision path.
- **Test**: determinism property tests; differential vs reference
  interpreter; corpus replay.
- **Gap**: "same state" needs a defined snapshot semantics —
  revocation/trust snapshots must be pinned per decision (spec/policy_ir).

### P12 Non-bypass by self-modification
- **Invariant**: no permitted action can alter policy, runtime
  binaries, interceptors, keys, or logs.
- **Enforcement**: TCB filesystem is outside the sandbox mount
  namespace; agent has no write path (test: attempt every write
  vector as scenarios).
- **Gap**: agent-controlled config *inputs* (e.g. policy reload via a
  permitted write) — policy must be signed or operator-written only.

### P13 Minimal TCB
- **Invariant**: TCB measured continuously — LoC, deps, privileged
  surface reported per release.
- **Test**: TCB metrics in Phase 5 report; dependency budget.
- **Gap**: "minimal" is comparative — report numbers, not adjectives.

## 5. Assumptions register

| ID | Assumption | Where it can fail |
|---|---|---|
| A-sign | Ed25519 signatures unforgeable; keys stay in TCB | Key compromise — out of scope, mitigate via rotation |
| A-kernel | Host kernel enforces namespaces/seccomp/caps | Kernel escape — sensitivity analysis tier |
| A-vmm | Container/microVM boundary holds | MicroVM escape — sensitivity tier |
| A-operator | Operator approval decisions are the ground truth for escalation | Social engineering — measured under H8 |
| A-clock | Monotonic time within ±Δ for expiry | Clock manipulation inside sandbox — must be prevented by seam |
| A-llm | LLM attacker unbounded *within* its action surface | Model-only channels (steganography in allowed outputs) — residual, documented |
| A-net | Proxy is sole egress path | Enforcement-dependent (P10) |
| A-spec | Scenario suite samples the real attack distribution | Coverage risk — held-out set + bypass ledger honesty |

## 6. Honest-residual register

Explicit non-goals recorded so nobody overclaims:
- Content-level steganography over allowed channels (A-llm residual).
- Speculative/side-channel exfil through shared hardware (outside TCB
  trust level).
- Social compromise of the operator endpoint itself.
- Semantic equivalence attacks where the *action is legal* but the
  composition is harmful — bounded by taint + quota, not eliminated.

## 7. Property organization — control layers (adopted from external review)

The 13 properties organize into four control layers, which the
research program reports against separately:

| Layer | Properties | Scientific question |
|---|---|---|
| **A — Authority** | P3, P4, P5 | Can the agent obtain authority it wasn't given? |
| **B — Execution** | P1, P2, P10, P12 | Can the agent cross the enforcement boundary? |
| **C — Accountability** | P7, P8, P9 | Can we know what actually happened? |
| **D — Control** | P6, P11, P13 | Can humans still control and reason about the system? |

### Control independence (new formalization)

A safety property is **control-independent** from the model when
violating it requires compromising an external trusted component —
not merely choosing a different agent behavior. Layers, weakest to
strongest:

    behavioral → policy → capability → runtime → kernel → hardware

The research question this names: at which layer does each P-property
become independent of the agent's internal policy? System A relies on
behavioral (prompt) control — not control-independent by definition.
System D's claim is that P1-P8 sit at runtime/kernel layer, where the
agent's *beliefs and choices* cannot affect the invariant.

### TCB attack-surface metric (P13 made quantitative)

Track and report per release: TCB LoC, dependency count, privileged
syscalls/interfaces, persistent-state surfaces, external services in
the trust boundary, network/IPC surface. Research question (the
review's sharpest one): does adding safety mechanisms paradoxically
grow attack surface? The metric answers it — mechanisms are adopted
only if they don't inflate the surface they defend.

# Adversarial spec review — v2 spec set v0.9 (2026-10-06)

Red-team pass over spec/* before Phase 2 builds on it. Findings are
spec-level weaknesses, not implementation bugs — each is either fixed
in-spec or carried as a declared residual.

Format: [finding] → attack it enables → disposition.

## F-SPEC-1 — `actor` is still credential-derived, not key-bound

**Threat model §1 + capability_token §3**: request_sig binds to a
signing keypair, but enrollment registers a pubkey *for* a principal —
if the enrollment path trusts the same bearer that provisioned the
token, an agent holding its own enrollment key could re-register a
fresh pubkey and rotate out of revocation history.
→ **Fix in spec**: enrollment pubkey must come from the operator's
provisioning channel, not self-asserted; re-keying requires operator
re-enrollment, never agent request. Key rotation is itself an audited
action type.

## F-SPEC-2 — `taint` trusts the labeler

action_model makes taint a first-class Action field. The taint layer
itself must be trusted — but who taints? If the agent's own tool-call
layer labels content, a compromised agent marks hostile input as
`operator-clean`.
→ **Spec gap, declared**: taint labels must be applied *at ingestion*
by the runtime seam, never by agent-supplied metadata. Where the
seam can't observe origin (agent-internal reasoning), the floor is
`untrusted` — explicit floor, not ambient trust. policy_ir's
`taint_max` selector stays sound only if taint is seam-assigned.

## F-SPEC-3 — Checkpoint push availability trade (audit_log §7)

"Checkpoint push fails → bounded queue → refuse new actions" makes
audit availability a DoS lever: an attacker who can disrupt the
off-host anchor channel stalls the agent entirely. That's a
**differential DoS**, acceptable per brief priorities (safety over
availability), but must be stated: an attacker controlling the anchor
channel halts work without needing to bypass policy.
→ **Kept, declared**: preferred over silent-degrade. Option: soft
mode where unanchored entries are flagged-not-fatal — a deployment
choice, recorded as operator-facing risk either way.

## F-SPEC-4 — DNS residual channel (P10/mechanism study)

netns+proxy egress deny still must resolve names *somewhere*. v1's
resolver path (SEC-0015) persists in v2 design — bounded covert
channel via DNS query names to the resolver.
→ **Residual, bounded**: resolver must be a stub that forwards ONLY
through the proxy's own upstream (no direct authoritative lookups from
agent), and query rates capped + logged. Covert bandwidth is bounded
by query rate × name length — measure it, publish the number,
don't claim zero.

## F-SPEC-5 — `agent_reason` still leaks evaluability

policy_ir §5 splits agent/operator reasons to bound T4's information
channel — good. But `coarse reason class` still distinguishes
`policy_denied` vs `capability_missing` vs `requires_approval` —
that's already enough signal for adaptive search to map the policy
boundary (try X → denied; add lease Y → escalates; the ORACLE is
the reason enum itself).
→ **Accepted with bound**: reason classes stay ≤ ~5 values;
deny-reason detail is the leak, so classes must collapse to the
point where the enum itself carries < 3 bits. Recorded as residual
for H7 measurement — if EC differs by reason class, the channel is
wide enough to matter.

## F-SPEC-6 — "Same state" snapshot semantics underspecified (P11)

policy_ir §6 pins state at decision time, but approvals resolve
against a *later* snapshot — an approval issued at T with trust
score X may resolve at T+Δ when trust has dropped. If the approval
check re-reads live state, stale approvals lose validity; if it
pins, revoked-between-issue-and-use must still fail.
→ **Fix in spec**: approval resolution checks `action_hash` +
operator_sig (pinned at issue) BUT re-checks `token.epoch` at
resolution time (revocation must win — approval granted pre-revoke
cannot land post-revoke). State pinning is asymmetric: content
pinned, liveness re-checked. approval_protocol.md updated to say so.

## F-SPEC-7 — `raw.unknown` is still a decision

action_model maps unparseable → `raw.unknown` → escalate-only.
But escalate means *an approver decides* — the classification is a
decision funnel for a parser bug: any parse failure lands in the
human's queue. Fuzzers become approval-fatigue amplifiers.
→ **Fix in spec**: `raw.unknown` requires a *second* triage step —
canonicalization failure itself is logged as a finding (it's a
spec-gap signal), and sustained unparseable rate triggers
self-test alarm (parser coverage regression), not just per-row
escalation.

## F-SPEC-8 — Biscuit choice uncommitted (capability_token §1)

Spec says "biscuit-go or fall back" — that's fine as a decision, but
the two formats have different revocation semantics (biscuit's
attenuation is verified; macaroon caveat checking needs a datalog
layer we haven't specced).
→ **Action item**, not spec fix: Phase 2 spike decides with a
concrete test; DECISIONS.md gets the call. Carried as open.

## F-SPEC-9 — Self-test inside the runtime can't detect runtime compromise

selftest §4 declares this residual — correct honesty. Second-order
risk: the *boot* check is also the first chain entry; a compromised
binary writes "all checks pass" as its first record. Chain integrity
doesn't help — the lie is inside a valid signature.
→ **Declared residual + mitigation**: external attestation point
(hardware key / second host) is the only real fix; spec marks it
OPTIONAL deployment requirement, not baseline.

## F-SPEC-10 — Scenario determinism vs LLM nondeterminism

preregistration's schema says `deterministic: true` for the artifact —
rightly qualified ("predicate + setup deterministic, agent path
stochastic"). Loose end: *seeded* stochasticity — attacker LLM runs
with recorded seeds where the provider supports it; where not,
n-runs needed anyway.
→ **Tightened**: schema gains `seed_policy: recorded|none`;
reproducibility claim is "same distribution", not "same run".

## Summary

10 findings: 3 spec fixes applied (F-SPEC-1, F-SPEC-6, F-SPEC-7),
3 declared residuals (F-SPEC-3, F-SPEC-4, F-SPEC-9), 2 bounded/
accepted (F-SPEC-2 floor rule, F-SPEC-5 ≤3-bit channel), 1 open
Phase-2 action (F-SPEC-8), 1 schema tightening (F-SPEC-10).

# Spec: Policy IR and semantics (v0.9)

Compiles POLICY.md (negative-capability rules) + positive grants into
a verifiable intermediate representation. Requirements from the brief:
deterministic, terminating, explainable, conflict-resolved,
default-posture configurable, statically analyzable.

## 1. Why an IR (not Rego, not YAML rules)

- POLICY.md is human-authored markdown — the *natural-language* source
  is authoritative for intent but unexecutable. IR is the compiled,
  executable artifact; the compiler keeps a source span map for
  explainability ("this denial came from POLICY.md §3 bullet 2").
- Cedar/OPA are backend *targets*: IR → Cedar is a Phase-2+ adapter
  for enterprise integration, not the core. Core stays ours, small,
  formally checkable (P13: tiny evaluator = small TCB).

## 2. IR shape

```
Rule := {
  id:         uuid            # stable, for explain + shadow analysis
  selector:   { type: TypeSet, resource: CanonPattern, env: EnvSet,
                actor: PrincipalSet, taint_max: TaintFloor }
  effect:     allow | deny | escalate | require_capability(Scope)
  provenance: SourceSpan      # POLICY.md offset or file:line
  priority:   explicit int    # no implicit ordering semantics
}
Policy := {
  version, rules: Rule[],
  default:  deny | escalate   # configurable; default deny
}
```

Semantics — single pass, total:
1. Collect all rules whose selector matches the canonical Action.
2. If any match has effect deny → deny (deny overrides always).
3. Else if any match has effect escalate → escalate.
4. Else if any match has effect require_capability → check token
   scope covers; else escalate.
5. Else if any allow → allow.
6. Else → default posture.

Order is total and deterministic: no rule ordering, no first-match
semantics. Identical rules by different priorities are a compile-time
conflict, not a runtime coin flip.

## 3. Selector semantics

- `type` matches on the closed enum exactly (no globs on type names —
  vocabulary is closed anyway).
- `resource` uses CanonicalPattern: host-label-boundary host matching,
  path prefix matching, explicit port class. Userinfo never
  canonicalizes (action_model §3.1) so no rule ever needs to handle it.
- `env` exact-match set membership.
- `taint_max`: action's taint must be ≤ floor — a rule can say
  "allow only if untainted" but never "allow BECAUSE tainted".

## 4. Conflict + shadow analysis (compile-time, required)

The compiler emits diagnostics, not silent semantics:
- **Shadowed rule**: rule R never matches anything rule R' doesn't
  match, where effect(R) loses precedence to effect(R') — warn, and
  emit the witness (a synthesized action matching R' only).
- **Contradiction**: same match set, both allow and deny → denied
  (safe) + diagnostic.
- **Unreferenced policy sections**: POLICY.md sections that produce
  zero IR rules → warn (doc drift detector).
- Analysis runs on every load; `--strict` makes warnings fatal.

## 5. Explainability — two channels

- **Agent-visible**: coarse reason class only (`policy_denied`,
  `requires_approval`, `capability_missing`). No selector detail —
  T4 attackers probe via denial reasons; don't hand them the map.
- **Operator-visible**: full trace — matched rules, source spans,
  which conjunct failed, counterfactual ("would allow if env=dev").
- This split is a security feature, not a UX choice. T4's adaptive
  search gets a bounded information channel.

## 6. Determinism (P11)

- Evaluator is a pure function: (Action, Policy, Snapshot) → Decision.
- Snapshot pins revocation epoch, trust scores, quotas — no mid-eval
  reads.
- Fuel-bounded evaluation: every rule eval counts steps; exceeding
  fuel = deny + alarm (never timeout→allow).
- Differential: `spec/policy_ir.md` ships a reference interpreter
  (~150 lines, intentionally naive); the fast evaluator must agree on
  the whole corpus. This is the P11 test harness.

## 7. POLICY.md grammar consumed by compiler

POLICY.md (the repo's existing doc) uses natural bullets. The compiler
accepts a *structured superset* — blocks marked ```policy fenced
sections with YAML bodies — while free prose stays informational.
Deviations between prose intent and compiled rules get flagged by the
unreferenced-sections check (§4). [ASSUMED: operator accepts this
grammar; document in DECISIONS.md if we formalize the fenced grammar.]

## 8. What this fixes vs v1

- v1 rule matching: per-rule first-match with implicit precedence —
  replaced by total order + explicit priorities (P11).
- v1 default-deny was config-driven; here the IR carries `default`
  explicitly and self-test verifies it.
- v1 rules couldn't express taint floors (new selector dimension).
- v1 escalation was a decision string; here `require_capability(Scope)`
  names the missing scope — approvals can attach exactly the right
  lease rather than a generic yes/no.

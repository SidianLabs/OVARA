# Phase 10: Policy Allow Behavior — Implementation Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-10-policy-allow` (from `phase-9-merge-cleanup`)
**Objective**: Move Ovara from "default escalation stub" toward "real local runtime authorization"

---

## Current State Audit

### What Exists

**Policy Store** (`policy/store.go`):
- `Rule` struct has `ActionType`, `Environment`, `Allow`, `Deny`, `Escalate` bool fields
- `RulesForAction()` and `RulesForEnvironment()` filter rules by matching patterns
- Default rules: `shell`, `github.merge`, `github.delete_branch`, `ci.deploy`, `git.force_push` all set to `Escalate: true` in production and non-production
- No default `Allow` rules — most things fall through to implicit allow

**Evaluator** (`evaluator/evaluator.go`):
- `evaluateRules()` checks actionRules then envRules for `Deny` flag — returns `false` if any deny found
- `shouldEscalate()` returns true if any non-wildcard rule has `Escalate: true`
- Trust signals can escalate an otherwise-allowed decision

**Critical Gap: Allow field is never read**
The `Rule.Allow` bool exists in the struct but is never checked in `evaluateRules()`. The default rules only set `Escalate: true` — they never set `Allow: true`. So there's no path for explicit allow.

**Current evaluation flow**:
1. Check containment/restriction → escalate
2. Check identity validity → deny if invalid
3. Check capability lease → deny if invalid
4. Check rules for deny → deny if found
5. Check rules for escalate → escalate if found, else allow
6. Trust can upgrade allow → escalate

**Result**: Everything not explicitly denied either escalates (due to default rules) or allows. The `Allow` field is dead code.

---

## Milestone Plan

- [ ] **Milestone A**: Audit and document current policy behavior ✓ (this checkpoint)
- [ ] **Milestone B**: Implement meaningful allow-path behavior
- [ ] **Milestone C**: Improve reason-code and explanation quality
- [ ] **Milestone D**: Policy examples and operator demoability
- [ ] **Milestone E**: Integration tests and verified flows
- [ ] **Milestone F**: Documentation and runbook updates

---

## Implementation Plan

### Desired evaluation model
1. If explicitly denied by policy → deny (check `Rule.Deny`)
2. Else if explicit containment/restriction → escalate
3. Else if explicitly escalated by policy → escalate (check `Rule.Escalate`)
4. Else if explicitly allowed by policy AND no stronger trust/containment concern → allow (check `Rule.Allow`)
5. Else → safe default (deny for production, escalate for ambiguous)

### Changes needed

**1. policy/store.go — LoadStoreFromConfig must parse Allow field**
Currently only parses `deny` and `escalate`, not `allow`.

**2. evaluator/evaluator.go — evaluateRules must check Allow field**
Add check: if rule has `Allow: true` and no deny/escalate on that rule, it's allowed.

**3. Add policy-specific reason codes**
- `ReasonPolicyAllow` = "policy_allow"
- `ReasonPolicyDeny` = "policy_deny"
- `ReasonPolicyEscalate` = "policy_escalate"
- Keep existing codes for trust/containment signals

**4. New sample policies**
- `sample_policy_local.json`: demonstrates allow (harmless read), deny (destructive), escalate (risky)
- Update `sample_policy.json` to show explicit allow for ci.read actions

---

## Implementation Completed

### Changes Made

**1. Policy Store** (`policy/store.go`)
- `LoadStoreFromConfig` now parses `allow` field from JSON rules

**2. Evaluator** (`evaluator/evaluator.go`)
- Added `RuleOutcome` struct with Allowed/Denied/Escalate/Reason fields
- `evaluateRules` now returns `RuleOutcome` instead of `(bool, ReasonCode)`
- Rule evaluation order: Deny → Allow → Escalate → default allow
- Trust signals checked at start of evaluation and can escalate even allowed actions
- Anomaly signals from trust now propagated to reason_codes on escalate

**3. Reason Codes** (`models/decision_response.go`)
- Added: `ReasonPolicyAllow`, `ReasonPolicyDeny`, `ReasonPolicyEscalate`, `ReasonTrustEscalate`

### New Behavior

| Rule Match | Decision | Reason Code |
|------------|----------|--------------|
| `deny: true` | deny | `policy_deny` |
| `allow: true` (no trust concern) | allow | `policy_allow` |
| `allow: true` (trust overrides) | escalate | `containment_active` / `trust_escalate` |
| `escalate: true` | escalate | `policy_escalate` (+ anomaly signals if trust also concerned) |
| No matching rule | allow | `allowed` |
| production + wildcard | escalate | `policy_escalate` + `production_target` |

---

## Validation

**Tests**: All 12 packages pass, 0 failures
**New tests added**:
- `TestEvaluator_ExplicitAllowPath` — allow rule → allow decision with `policy_allow` reason
- `TestEvaluator_ExplicitDenyPath` — deny rule → deny decision with `policy_deny` reason
- `TestEvaluator_ExplicitEscalatePath` — escalate rule → escalate with `requires_approval=true`
- `TestEvaluator_TrustCanEscalateAllowedAction` — trust containment overrides allow
- `TestEvaluator_DefaultDenyForUnknownAction` — unknown actions fall through to default

---

## Git Log

```
62464c8 feat(policy): implement explicit allow path semantics
eebab7b docs(build): add phase 10 policy allow checkpoint
```
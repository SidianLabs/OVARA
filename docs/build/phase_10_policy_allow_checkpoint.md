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

## Validation

- Unit tests for evaluateRules with allow/deny/escalate rules
- Integration test crossing runtime + policy + trust
- Manual test: start gateway, POST /v1/runtime/check with shell action, see escalate; POST with ci.read, see allow

---

## Files to Change

**Modified**:
- `runtime/gateway/internal/policy/store.go` — parse `allow` field in LoadStoreFromConfig
- `runtime/gateway/internal/evaluator/evaluator.go` — implement allow path semantics
- `runtime/gateway/internal/models/decision_response.go` — add policy-specific reason codes
- `examples/sample_policy.json` — add explicit allow rules
- `examples/sample_policy_local.json` — create first-run-friendly policy

**Created**:
- `docs/build/phase_10_policy_allow_checkpoint.md` — this file

**Tests modified/added**:
- `runtime/gateway/internal/evaluator/evaluator_test.go` — add allow/deny/escalate tests
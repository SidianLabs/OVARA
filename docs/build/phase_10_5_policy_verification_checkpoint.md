# Phase 10.5: Policy Verification and Consistency Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-10-5-policy-verification` (from `phase-10-policy-allow`)
**Objective**: Verify policy allow behavior is correct and consistent

---

## Milestone A: Resolve Policy Default Semantic Ambiguity

**Issue found**: Test named `TestEvaluator_DefaultDenyForUnknownAction` suggested deny was the default, but code returned allow.

**Resolution**:
- Renamed test to `TestEvaluator_DefaultAllowForUnknownAction` - clarifies actual behavior
- Added `TestEvaluator_DefaultEscalateForProductionUnknownAction` - documents that default rules escalate production shell
- Added `TestEvaluator_PolicyExplicitAllowVoucher` - verifies explicit allow works with config

**Final default behavior**:
- No matching rule in non-production → `DecisionAllow` with `ReasonAllowed`
- No matching rule in production (with default rules) → `DecisionEscalate` with `ReasonPolicyEscalate` + `ReasonProductionTarget`

---

## Milestone B: Verify Action Type / Documentation Consistency

**Canonical action types** (from `models/action_request.go`):
- `shell`, `git.push`, `git.pull`, `git.force_push`
- `github.push`, `github.pr`, `github.merge`, `github.delete_branch`
- `ci.deploy`, `ci.build_trigger`, `ci.approval`

**Doc updates needed**: None required - existing usage is consistent.

---

## Milestone C: Real File-Backed Policy Verification

**Critical bug found and fixed**: `evaluateRules` was not checking environment match in `actionRules` and action match in `envRules` when evaluating. This caused:
- `shell/local` rule to be matched against `shell/production` request (deny-first check)
- `git.force_push/*` env rule to be matched against any action type (deny-first check)

**Before fix**: Policy file loaded correctly, but evaluation was wrong.
**After fix**: All three outcomes (allow, deny, escalate) work correctly with file-backed policy.

**Commands run and results**:
```
# Test 1: shell in local → ALLOW (policy_allow)
curl -X POST .../v1/runtime/check -d '{"action_type":"shell","environment":"local",...}'
→ {"decision":"allow","reason_codes":["policy_allow"]}

# Test 2: shell in dev → ESCALATE (policy_escalate)
curl -X POST .../v1/runtime/check -d '{"action_type":"shell","environment":"dev",...}'
→ {"decision":"escalate","reason_codes":["policy_escalate"],"requires_approval":true}

# Test 3: shell in production → DENY (production_denied)
curl -X POST .../v1/runtime/check -d '{"action_type":"shell","environment":"production",...}'
→ {"decision":"deny","reason_codes":["production_denied"]}

# Test 4: git.pull in local → ALLOW (policy_allow)
curl -X POST .../v1/runtime/check -d '{"action_type":"git.pull","environment":"local",...}'
→ {"decision":"allow","reason_codes":["policy_allow"]}

# Test 5: git.force_push in dev → DENY (policy_deny)
curl -X POST .../v1/runtime/check -d '{"action_type":"git.force_push","environment":"dev",...}'
→ {"decision":"deny","reason_codes":["policy_deny"]}
```

**Test policy file**: `/tmp/full_test.json`
```json
{
  "version": "v1-full-test",
  "rules": [
    {"action_type": "shell", "environment": "local", "allow": true},
    {"action_type": "shell", "environment": "dev", "escalate": true},
    {"action_type": "shell", "environment": "production", "deny": true},
    {"action_type": "git.pull", "environment": "*", "allow": true},
    {"action_type": "git.force_push", "environment": "*", "deny": true}
  ]
}
```

---

## Milestone D: Explanation Quality Tightening

**Fix applied to evaluateRules**:
- `actionRules` now check environment match: `r.Environment == "*" || r.Environment == string(req.Environment)`
- `envRules` now check action match: `r.ActionType == "*" || r.ActionType == string(req.ActionType)`
- This ensures rules only match when BOTH action AND environment criteria are met

**Reason codes are now consistent**:
- `policy_allow` for explicit allow rules
- `policy_deny` for explicit deny rules
- `production_denied` for production deny
- `policy_escalate` for explicit escalate rules

---

## Milestone E: Final Docs/Test Alignment

**Test updates**:
- `TestEvaluator_DefaultDenyForUnknownAction` → `TestEvaluator_DefaultAllowForUnknownAction`
- Added `TestEvaluator_DefaultEscalateForProductionUnknownAction`
- Added `TestEvaluator_PolicyExplicitAllowVoucher`
- Added `TestLoadStoreFromFile_AllowRules` in policy package

**All tests pass**: 12 packages, 0 failures

---

## Files Changed

**Modified**:
- `runtime/gateway/internal/evaluator/evaluator.go` - fixed evaluateRules to check env/action match properly
- `runtime/gateway/internal/evaluator/evaluator_test.go` - renamed/added tests for correct semantics
- `runtime/gateway/internal/policy/file_store_test.go` - added TestLoadStoreFromFile_AllowRules

---

## Git Log

```
phase-10-5-policy-verification:
(commits will be listed at end of pass)
```
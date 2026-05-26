# Phase 46-52 Policy Management — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-46-52-policy-management`
**Parent**: `phase-31-38-verification` (commit `151531d`)
**Objective**: Make policy authoring safer, testable, and more understandable before affecting live runtime behavior

---

## 1. Repository Verification

- **Current branch**: `phase-46-52-policy-management`
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Latest commits reviewed**:
  - `151531d` docs(build): finalize phase 31-38 verification and phase 39-45 checkpoint
  - `fc590bf` feat(admin): add dry-run, audit events, integrity codes, snapshot hardening, recovery docs
  - `2b291ef` test(runtime): add integrity/admin/snapshot verification tests and fix summarize bug

---

## 2. Implementation Summary

### What's Implemented

**Policy Validation** (`POST /v1/policy/validate`):
- Validates policy JSON structure (version required, rules required)
- Checks each rule for: action_type/environment presence, allow+deny contradiction, no-effect
- Generates warnings for: empty ruleset, wildcard+specific mixing, allow/deny conflicts across rules
- Returns `{valid, errors[], warnings[]}`

**Policy Simulation** (`POST /v1/policy/simulate`):
- Simulates a single request against a candidate or current policy
- Returns decision (allow/deny/escalate), reason, trust score, policy version
- Supports inline `candidate_policy` (base64), `candidate_file` path, or staged candidate
- Does not affect live policy

**Batch Simulation** (`POST /v1/policy/simulate-batch`):
- Simulates multiple requests at once
- Shows current vs candidate decision for each request
- Reports `changed_count` and `unchanged_count`
- Useful for regression testing a policy change

**Policy Diff** (`GET/POST /v1/policy/diff`):
- Structural diff between current and candidate policy
- Reports `added_rules`, `removed_rules`, `changed_rules`
- Supports inline candidate or file path

**Candidate/Staged Workflow**:
- `POST /v1/policy/candidate/load` — stages a policy (validates first)
- `POST /v1/policy/candidate/promote` — replaces live policy with staged candidate
- `GET /v1/policy/rules` — lists current rules (shows if candidate loaded)
- Staged candidate is used by simulate/simulate-batch when `use_current=false` and no explicit candidate given

**Policy Audit Events**:
- `policy.validated` — emitted on validate
- `policy.simulated` — emitted on simulate
- `policy.diff_generated` — emitted on diff
- `policy.candidate_loaded` — emitted on candidate load
- `policy.promoted` — emitted on promote

### Candidate Policy Limitations (Documented in Runbook)

- **Not persistent**: stored in package-level Go variable, does not survive restart
- **Single gateway only**: each gateway instance maintains its own candidate state
- **No file on disk**: candidate exists only in running process memory
- **Rollback procedure**: load and promote original file if rollback needed

---

## 3. Bugs Fixed During Verification

1. **`filePolicyLite` JSON unmarshaling**: `filePolicyLite` used `[]policy.Rule` which has uppercase fields with no JSON tags. Fixed by using a local `fileRule` struct with proper lowercase JSON tags.

2. **`parsePolicyJSON` default rules**: `policy.NewStore()` initializes with default rules. Fixed by calling `store.ClearRules()` after creation.

3. **Simulate not using staged candidate**: When `use_current=false` and no explicit candidate provided, simulate didn't fall back to staged candidate. Fixed by adding `else if candidatePolicyStore != nil` branch.

4. **Same fix for SimulateBatch**: Applied the same staged candidate fallback fix to batch simulate.

5. **Missing POST route for `/v1/policy/diff`**: Only GET was registered. Fixed by adding POST route registration.

6. **PolicyHandler not wired into main.go**: Handler existed but wasn't instantiated or registered. Fixed by adding to main.go setup.

---

## 4. Files Created/Modified

### Created
- `runtime/gateway/internal/policy/validator.go` — validation/linting logic
- `runtime/gateway/internal/policy/validator_test.go` — 16 validator tests
- `runtime/gateway/internal/handlers/policy.go` — policy management endpoints
- `runtime/gateway/internal/handlers/policy_test.go` — 6 handler tests

### Modified
- `runtime/gateway/cmd/server/main.go` — wired PolicyHandler into server
- `runtime/gateway/internal/policy/store.go` — added `ClearRules()` method
- `runtime/gateway/internal/handlers/policy.go` — bug fixes and staged candidate support
- `docs/developer/runtime_examples.md` — added policy management runbook (~250 lines)

---

## 5. Live Verification Results

All endpoints verified with curl against running gateway:

```
=== GET /v1/policy/rules ===
{"version":"v1-local","rules":[...],"candidate_loaded":false}

=== POST /v1/policy/validate ===
{"valid":true,"warnings":["policy mixes wildcard..."]}

=== POST /v1/policy/simulate (current) ===
{"decision":"escalate","reason":"policy_escalate"...}

=== POST /v1/policy/simulate (candidate allow shell:local) ===
{"decision":"allow","reason":"policy_allow","policy_version":"v1-test"...}

=== POST /v1/policy/simulate-batch ===
{"results":[...],"total_count":2,"changed_count":2,"unchanged_count":0...}

=== POST /v1/policy/diff ===
{"from_version":"v1-local","to_version":"v1-strict","added_rules":[...]...}

=== POST /v1/policy/candidate/load ===
{"version":"v1-candidate","rules_count":1,"loaded":true}

=== POST /v1/policy/simulate (after load, uses staged candidate) ===
{"decision":"allow","policy_version":"v1-candidate"...}

=== POST /v1/policy/candidate/promote ===
{"status":"promoted","version":"v1-candidate","rules":1}

=== GET /v1/policy/rules (after promote) ===
{"version":"v1-candidate","rules_count":1...}
```

---

## 6. Tests

### Policy Validator Tests (16 tests)
- Valid policy passes
- Invalid JSON fails with error
- Missing version fails
- Empty rules generates warning
- Empty action_type/environment fails
- No-effect rule fails
- Contradictory (allow+deny) fails
- Wildcard mixing generates warnings
- ValidateRule tests (valid, empty fields, no-effect, contradictory)
- ValidateRules tests (valid list, empty list)
- FormatErrors test
- Real policy file roundtrip test

### Policy Handler Tests (6 tests)
- Simulate single request
- List rules
- Method not allowed (GET on POST endpoint)
- Simulate with decision changes between current/candidate
- Validator rule validation
- Validator rules validation

### All Tests Passing
```
ok  ovara.runtime.gateway/internal/policy      0.189s
ok  ovara.runtime.gateway/internal/handlers  1.111s
ok  ovara.runtime.gateway/internal/evaluator 0.504s
```

---

## 7. What's Intentionally Not Implemented

- **Persistent candidate policy store**: Candidate is in-memory only by design (local-only, lightweight)
- **Multi-gateway candidate sync**: Each gateway maintains its own candidate state
- **Policy distribution**: Policy is loaded from local file only; no remote distribution
- **OPA/Cedar integration**: Custom simple matching model used; extensibility point exists
- **API versioning for policy endpoints**: Uses `/v1/policy/` prefix; no `/v2/`

---

## 8. Merge Recommendation

**Ready to merge.**

The phase is complete with:
- All 6 policy management endpoints implemented and live-verified
- 22 new tests passing
- Bug fixes for JSON unmarshaling, default rules, staged candidate fallback, missing route registration, unwired handler
- Comprehensive runbook documenting all endpoints and candidate limitations
- Checkpoint documenting bugs found and fixed

### Branch
- `phase-46-52-policy-management` from `phase-31-38-verification`

### Suggested Commits
1. `fix(policy): wire PolicyHandler into main.go and fix JSON unmarshaling bugs`
2. `fix(policy): add missing POST route for diff, staged candidate fallback, ClearRules`
3. `test(policy): add validator tests and handler tests`
4. `docs(runtime): complete policy management runbook`
5. `docs(build): finalize phase 46-52 checkpoint`

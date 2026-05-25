# Phase 11: Runtime Polish and Verification Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-11-runtime-polish` (from `phase-10-5-policy-verification`)
**Objective**: Make the local runtime more trustworthy, observable, and cleaner to operate

---

## Milestone Plan

- [ ] **Milestone A**: Hot reload end-to-end verification
- [ ] **Milestone B**: Runtime/operator observability tightening
- [ ] **Milestone C**: Dead code and stale seam cleanup
- [ ] **Milestone D**: Explanation quality and debugging ergonomics
- [ ] **Milestone E**: Tests and docs alignment

---

## Current State

**Hot reload path**:
1. main.go creates `LocalFileSource` with file path and store
2. On file write event via fsnotify, main.go calls `watcher.Reload()`
3. `Watcher.Reload()` calls `source.Reload()`
4. `LocalFileSource.Reload()` calls `store.Reload()`
5. `Store.Reload()` reloads rules from file with mutex held

**Current status endpoint fields** (runtime.go:288):
- gateway_id, gateway_name, gateway_version, enrollment_status
- decision_cache_count, decision_cache_max
- receipt_count

**Missing observability**:
- No policy_version in status response
- No last_reload_time or reload_error
- No policy_source (file vs in-memory)
- No storage mode indicator
- No pending approval count
- No restricted agent count (only list, no aggregate)

**Dead code candidates**:
- `shouldEscalate` in evaluator (always returns false)
- Default rules in store.go may conflict with explicit policy behavior

---

## Hot Reload Verification Plan

1. Build current binary
2. Start gateway with policy file and hot reload enabled
3. Test initial decision outcome
4. Modify policy file to change outcome
5. Verify decision changes without restart
6. Test malformed policy reload behavior
---

## Hot Reload Verification Results

**Test 1: Allow → Deny change**
- Initial: shell/local → allow (policy_allow)
- Modified policy: shell/local → deny
- After reload: shell/local → deny (policy_deny)
- Status: VERIFIED ✓

**Test 2: Deny → Allow change**
- Modified policy: shell/local → allow
- After reload: shell/local → allow (policy_allow)
- Status: VERIFIED ✓

**Test 3: Malformed JSON reload**
- Malformed policy written
- Gateway logged: "policy reload failed: failed to parse policy JSON"
- Last good policy retained
- Status: VERIFIED ✓ (fails safely)

---

## Status Endpoint Improvements

**New fields added**:
- `policy_version` - current policy version string
- `policy_source` - "file:/path" or "in-memory"
- `policy_refresh_secs` - hot reload interval
- `hot_reload` - "enabled" or "disabled"
- `storage_mode` - "file-backed" or "in-memory"

**Example response**:
```json
{
  "gateway_id": "gw_360000",
  "gateway_name": "local-gateway",
  "gateway_version": "0.8.0",
  "policy_version": "v1-final-test",
  "policy_source": "file:/tmp/policy_reload.json",
  "policy_refresh_secs": 2,
  "hot_reload": "enabled",
  "storage_mode": "file-backed",
  "decision_cache_count": 0,
  "decision_cache_max": 10000,
  "receipt_count": 0
}
```

---

## Evaluation Summary

**New field**: `evaluation_summary` in DecisionResponse

**Values**:
- "allowed by explicit policy rule" - policy_allow
- "allowed by default (no matching deny/escalate rule)" - default allow
- "denied by production policy rule" - production_denied
- "denied by explicit policy rule" - policy_deny
- "denied: invalid or missing agent identity" - identity_invalid
- "denied: capability validation failed" - capability issues
- "escalated: agent is restricted or contained" - containment_active
- "escalated: low trust score or anomaly detected" - trust_escalate
- "escalated by explicit policy rule" - policy_escalate
- "escalated: requires approval" - default escalate

---

## Dead Code Removed

- `shouldEscalate` function (always returned false, unused)

---

## Git Log

```
1474fdf feat(runtime): improve status endpoint and fix hot reload
```

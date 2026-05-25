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
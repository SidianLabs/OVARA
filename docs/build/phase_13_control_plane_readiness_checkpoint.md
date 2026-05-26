# Phase 13: Control-Plane Readiness Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-13-control-plane-readiness` (from `phase-12-enrollment-foundations`)
**Objective**: Make enrollment/control-plane foundation more operationally real

---

## Milestone Plan

- [x] **Milestone A**: Heartbeat and liveness
- [x] **Milestone B**: Config and identity coherence
- [x] **Milestone C**: Status summary enrichment
- [x] **Milestone D**: Enrollment persistence path clarity
- [ ] **Milestone E**: Docs and operator runbook

---

## Implementation Results

### Milestone A: Heartbeat and Liveness

**Changes to `runtime/gateway/internal/enrollment/service.go`**:
- Added `StartHeartbeat(interval time.Duration) func()` to Service interface
- Implemented periodic heartbeat goroutine with ticker
- Returns stop function for graceful shutdown
- `LastSeenAt` now updates every `HeartbeatIntervalSec` (default 30s)
- Persists enrollment state on each heartbeat tick

**Changes to `runtime/gateway/cmd/server/main.go`**:
- Starts heartbeat on enrollment service at startup
- Stops heartbeat gracefully on SIGINT/SIGTERM
- Logs heartbeat startup with configured interval

**New tests**:
- `TestLocalService_StartHeartbeat` - verifies periodic updates
- `TestLocalService_StartHeartbeat_Stop` - verifies clean stop behavior

**Behavior verified**:
- Heartbeat starts with default 30s interval
- LastSeenAt updates automatically over time
- Graceful stop on signal

### Milestone B: Config and Identity Coherence

**Changes to `runtime/gateway/internal/config/config.go`**:
- Added `EnrollmentFile string` field (default: `var/data/enrollment.json`)
- Added `HeartbeatIntervalSec int` field (default: 30)

**Enrollment file path is now explicit**:
- No longer derived from receipts file path
- Falls back to `var/data/enrollment.json` if not configured
- Allows operator to control where enrollment state is stored

**Identity coherence via functional options**:
- `enrollment.NewLocalService(filePath, opts...)` accepts options
- `WithGatewayName(name)` - sets gateway name from config
- `WithGatewayVersion(version)` - sets version from config
- Main.go wires `cfg.GatewayName` and `cfg.GatewayVersion` into enrollment

**Before**:
```go
enrollmentSvc := enrollment.NewLocalService(enrollmentFile)  // always "local-gateway", "0.9.0"
```

**After**:
```go
enrollmentSvc := enrollment.NewLocalService(enrollmentFile,
    enrollment.WithGatewayName(cfg.GatewayName),
    enrollment.WithGatewayVersion(cfg.GatewayVersion),
)
```

### Milestone C: Status Summary Enrichment

**Status endpoint now returns**:
- `gateway_id`, `gateway_name`, `gateway_version` (from enrollment identity)
- `enrollment_state`, `environment`
- `registered_at`, `last_seen_at`, `last_seen_age_secs`
- `enrollment_healthy` (from enrollment status)
- `enrollment_file` (configured enrollment file path)
- `policy_version`, `policy_source`, `policy_refresh_secs`, `hot_reload`
- `storage_mode`
- `decision_cache_count`, `decision_cache_max`
- `receipt_count`
- `pending_approval_count` (from approval service)
- `shield_restricted_agents`, `shield_total_agents` (from shield store)

**Handler methods added**:
- `SetApprovalStats(*approval.Service)` - wires approval service for pending count
- `SetShieldStats(func() (restricted, total int))` - wires shield store for stats

**Actual status output**:
```json
{
  "decision_cache_count": 0,
  "decision_cache_max": 10000,
  "enrollment_file": "",
  "enrollment_healthy": true,
  "enrollment_state": "local",
  "environment": "local",
  "gateway_id": "gw_707000",
  "gateway_name": "local-gateway",
  "gateway_version": "0.9.0",
  "hot_reload": "disabled",
  "last_seen_age_secs": 1.304866,
  "last_seen_at": "2026-05-25T05:40:22.08568Z",
  "pending_approval_count": 0,
  "policy_refresh_secs": 0,
  "policy_source": "in-memory",
  "policy_version": "v1-local",
  "receipt_count": 0,
  "registered_at": "2026-05-25T05:40:22.08568Z",
  "shield_restricted_agents": 0,
  "shield_total_agents": 0,
  "storage_mode": "in-memory"
}
```

### Milestone D: Enrollment Persistence Path Clarity

**Before**:
- Enrollment file derived indirectly from `cfg.ReceiptsFile`
- Path construction: `receiptsFile[:len(receiptsFile)-len(filepath.Base(receiptsFile))] + "enrollment.json"`

**After**:
- `cfg.EnrollmentFile` is explicit and independent
- Default: `var/data/enrollment.json`
- No derivation from receipts path
- Operator can set via config JSON

**Startup logs now show**:
```
enrollment heartbeat started (default interval=30s)
gateway_id=gw_707000 enrollment_state=local environment=local
receipts in-memory (no persistence configured)
approvals in-memory (no persistence configured)
```

---

## Files Changed

**Created**:
- (none)

**Modified**:
- `runtime/gateway/internal/enrollment/service.go` - StartHeartbeat, functional options, default name/version
- `runtime/gateway/internal/enrollment/service_test.go` - heartbeat tests
- `runtime/gateway/internal/config/config.go` - EnrollmentFile, HeartbeatIntervalSec fields
- `runtime/gateway/internal/handlers/runtime.go` - SetApprovalStats, SetShieldStats, enriched status
- `runtime/gateway/internal/approval/service.go` - ListByStatus public method
- `runtime/gateway/internal/trust/shield.go` - Stats() method
- `runtime/gateway/cmd/server/main.go` - wire heartbeat, approval stats, shield stats; remove filepath import

---

## Tests

**New tests in enrollment**:
- `TestLocalService_StartHeartbeat` - verifies periodic last_seen updates
- `TestLocalService_StartHeartbeat_Stop` - verifies ticker stops on returned func call

**All tests pass**:
```
ok  ovara.runtime.gateway/internal/enrollment  0.855s (9 tests)
ok  ovara.runtime.gateway/internal/handlers   1.529s
ok  ovara.runtime.gateway/internal/trust      3.049s
```

---

## What's Stubbed vs Real

**Real**:
- Periodic heartbeat updates last_seen_at every 30s
- Graceful stop of heartbeat on shutdown
- Config-driven enrollment file path
- Config-driven gateway name/version via options
- Full status summary with approval counts and shield stats
- Approval service wired to handler for pending count
- Shield store Stats() method for restricted/total agent counts

**Still local-only**:
- No actual remote control plane enrollment
- Enrollment identity still local, not cloud-managed
- Heartbeat just updates timestamps, no external communication

---

## Git Log

```
[on branch phase-13-control-plane-readiness]
(no commits yet on this branch - work in progress)
```

---

## Next Steps

- [ ] Milestone E: Document enrollment heartbeat behavior, status fields, and persistence path
- [ ] Verify heartbeat persists across restarts
- [ ] Test with configured enrollment file path to ensure directory creation works
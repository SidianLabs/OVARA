# Phase 12: Enrollment Foundations Checkpoint

**Date**: 2026-05-25
**Branch**: `phase-12-enrollment-foundations` (from `phase-11-runtime-polish`)
**Objective**: Build local control-plane foundations and gateway enrollment model

---

## Milestone Plan

- [ ] **Milestone A**: Gateway identity model
- [ ] **Milestone B**: Local enrollment state
- [ ] **Milestone C**: Status and operator visibility
- [ ] **Milestone D**: Interface and seam cleanup
- [ ] **Milestone E**: Docs and local runbook

---

## Current State

**Existing enrollment-related code**:
- `config.Enrollment` struct with GatewayID, GatewayName, Version, Status, EnrolledAt, LastSeenAt, ControlPlaneURL
- `EnrollmentStatusLocal`, `EnrollmentStatusEnrolled`, `EnrollmentStatusPending` constants
- `Enrollment.IsLocal()`, `Enrollment.IsEnrolled()` methods
- Status field is hardcoded to "local" in runtime.go handleGetStatus

**Current status endpoint fields**:
- gateway_id, gateway_name, gateway_version
- enrollment_status (hardcoded to "local")
- policy_version, policy_source, policy_refresh_secs, hot_reload
- storage_mode
- decision_cache_count, decision_cache_max
- receipt_count

**Missing for enrollment model**:
- No EnrollmentService interface
- No local enrollment state persistence
- No gateway identity beyond ID and name
- No way to mark gateway as "enrolled" vs "local-only"
- Status doesn't show restricted agent count or pending approval count

---

## Implementation Plan

### Milestone A: Gateway Identity Model

**New package**: `runtime/gateway/internal/enrollment/`

**EnrollmentService interface**:
```go
type EnrollmentService interface {
    GetIdentity() *GatewayIdentity
    GetStatus() *EnrollmentStatus
    Initialize(env string) error
    Heartbeat() error
    IsEnrolled() bool
}
```

**GatewayIdentity struct**:
```go
type GatewayIdentity struct {
    ID            string    // gateway unique ID
    Name          string    // human-readable name
    Version       string    // runtime version
    Environment   string    // local/dev/staging/production
    RegisteredAt  time.Time // when first registered
    LastSeenAt    time.Time // last heartbeat
    EnrollmentState EnrollmentState // local/enrolled/pending
    Tags          map[string]string // metadata labels
}

type EnrollmentState string
const (
    EnrollmentStateLocal     EnrollmentState = "local"
    EnrollmentStateEnrolled   EnrollmentState = "enrolled"
    EnrollmentStatePending    EnrollmentState = "pending"
)
```

### Milestone B: Local Enrollment State

**LocalEnrollmentService**:
- Implements EnrollmentService
- Stores state in var/data/enrollment.json
- On startup, loads or initializes enrollment
- Heartbeat updates LastSeenAt
- Provides a local stand-in for future control-plane enrollment

### Milestone C: Status Visibility

**Enhanced status endpoint**:
- enrollment_state
- registered_at
- last_seen_at
- environment
- restricted_agent_count
- pending_approval_count (from approval store)
- trust_summary (aggregate shield stats)

### Milestone D: Interface Alignment

- Ensure stores/services have clear control-plane-ready interfaces
- Align naming: EnrollmentService, PolicySource, ShieldStore

### Milestone E: Documentation

- Document enrollment model meaning locally
- Explain what status fields mean
- Clarify what's stubbed vs real for future cloud

---

## Files to Change

**Created**:
- `runtime/gateway/internal/enrollment/`
  - `service.go` — EnrollmentService interface and LocalEnrollmentService
  - `identity.go` — GatewayIdentity and EnrollmentState types
  - `store.go` — File-backed enrollment persistence
  - `service_test.go`

**Modified**:
- `runtime/gateway/internal/config/config.go` — add Environment and Tags to Enrollment
- `runtime/gateway/internal/handlers/runtime.go` — expose enrollment info in status
- `runtime/gateway/cmd/server/main.go` — wire enrollment service

**Tests**:
- `runtime/gateway/internal/enrollment/service_test.go`

---

## Validation

- Build and test after each milestone
- Run full test suite at end
- Verify enriched status output via curl
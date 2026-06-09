# Phase 65 V1 Hardening & Cleanup — Checkpoint

**Branch:** `phase-65-v1-hardening`
**Base:** `phase-64-v1-polish`
**Date:** 2026-06-09
**Status:** Complete — all tasks executed, full suite passes under `-race`

## Summary

Phase 65 addressed all remaining risks flagged in the Phase 64 V1 Polish checkpoint. The primary change was removing the legacy `MarkReady`/`IsReady` method names and replacing them with `MarkQueued`/`IsQueued` for consistency with the `StateQueued` constant. Several tasks revealed that their concerns had already been addressed in Phase 64.

## Changes

### Task 65.1 — Remove Legacy `ready` State Naming

The `StateReady` constant was already removed in Phase 64, but the legacy method names `MarkReady()` and `IsReady()` remained as aliases that delegated to queued semantics. This caused confusion and inconsistency.

**Changes:**
- `continuation/store.go`: Renamed `MarkReady()` → `MarkQueued()`, removed `IsReady()`, added `IsQueued()`
- `handlers/approval.go`: Updated call from `MarkReady()` → `MarkQueued()`
- `handlers/execution_diagnostics_test.go`: Updated 2 call sites
- `continuation/store_test.go`: Updated 13 call sites and test function name
- `handlers/continuations.go`: Updated cancel error message
- 0 remaining references to `MarkReady` or `IsReady` in Go source

### Task 65.2 — Panic Recovery in Orchestrator

The `executeOne` method in `orchestrator.go` already included a `defer recover()` block that catches executor panics, marks the execution as failed, and logs the panic. Added a dedicated test `TestOrchestrator_ExecutorPanic_RecoversAndMarksFailed` verifying:
- Continuation transitions to `StateExecuted` (retryable) after panic
- Execution record created with `StateFailed`
- Error message populated from panic value

### Task 65.3 — executing_breaching in Health SLA

Already implemented in Phase 64. The `addSLABreaches()` function computes `executing_breaching` and `handleGetHealth` surfaces it via the `sla` key. Verified with existing test `runtime_sla_test.go`.

### Task 65.4 — Integration Test Suite

Already comprehensive at 880+ lines in `runtime_integration_test.go`. Covers:
- Safe action → allow decision
- Risky action → escalate with trust anomaly reasons
- Restricted agent → escalate with containment
- Approval creation and correlation
- Receipt generation and retrieval
- Metrics endpoint shape
- Snapshot endpoint shape
- Integrity endpoint
- Trace endpoint by decision/continuation/execution/approval/receipt IDs
- Summary endpoint with approval counts
- Capability correlation in trace

### Task 65.5 — Linter

```
go vet -all ./...  → clean (runtime/gateway + identity)
```

### Task 65.6 — Godoc Comments

All exported symbols already have doc comments from prior phases. No changes needed.

### Task 65.7 — Benchmarks

Added `handlers/benchmark_test.go` with 10 benchmarks:

| Benchmark | Result (Apple M4) | Notes |
|-----------|-------------------|-------|
| `RuntimeCheck_PolicyOnly` | 5,374 ns/op | Simplest path (git.pull in dev) |
| `RuntimeCheck_WithIdentity` | 6,126 ns/op | With agent identity validation |
| `RuntimeCheck_WithTrustAnomaly` | 6,210 ns/op | With risky pattern matching |
| `RuntimeCheck_WithCapabilityLease` | 7,669 ns/op | Full identity + lease evaluation |
| `Evaluator_Evaluate` | 1,271 ns/op | Direct evaluator (no HTTP) |
| `Evaluator_Evaluate_Risky` | 1,235 ns/op | With anomaly pattern matching |
| `ReceiptSigner_Sign` | 598 ns/op | HMAC-SHA256 signing |
| `ReceiptSigner_Verify` | 614 ns/op | HMAC-SHA256 verification |
| `DecisionCache_Put` | 38 ns/op | Cache insertion |
| `DecisionCache_Get` | 39 ns/op | Cache retrieval |

## Validation

```
runtime/gateway:
  go build ./...              → clean
  go vet -all ./...           → clean
  go test -race ./...         → 22/22 packages passing
  go test -bench=. ./internal/handlers/ → 10 benchmarks passing

identity:
  go build ./...              → clean
  go vet -all ./...           → clean
  go test -race ./...         → 1/1 package passing
```

## Files Changed

| File | Change |
|------|--------|
| `continuation/store.go` | Renamed `MarkReady`→`MarkQueued`, removed `IsReady`, added `IsQueued` |
| `continuation/store_test.go` | Updated 13 call sites, renamed test function |
| `continuation/orchestrator_test.go` | Added `TestOrchestrator_ExecutorPanic_RecoversAndMarksFailed` |
| `handlers/approval.go` | Updated `MarkReady`→`MarkQueued` |
| `handlers/execution_diagnostics_test.go` | Updated 2 call sites |
| `handlers/continuations.go` | Updated cancel error message |
| `handlers/benchmark_test.go` | NEW: 10 benchmarks |

## Remaining Risks

None. All Phase 64 flagged risks are resolved.

## Next Phase

**Phase 66: Identity Integration Deepening** — Wire full ed25519 signature verification and delegation chain cryptographic validation into the gateway evaluator.

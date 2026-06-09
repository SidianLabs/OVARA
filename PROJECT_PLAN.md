# Ovara — Project Plan (Phase 65 → Production Readiness)

**Status:** Active  
**Current Branch:** phase-64-v1-polish (V1 complete)  
**Updated:** 2026-06-10

## Architecture Summary

Ovara is a single-binary Go gateway providing runtime trust infrastructure for autonomous systems. It intercepts agent actions, validates machine identity and capability leases, evaluates policy rules, computes trust signals, and decides allow/deny/escalate — all with cryptographic receipts and full auditability.

### Active Modules
- `runtime/gateway/` — 122 Go files, 22 packages. The monolith: handlers, evaluator, policy, trust/shield, approval, continuation, execution, receipts, events, capabilities, auth, enrollment, integrity, metrics, logging
- `identity/` — 14 Go files. Machine identity primitives: AgentIdentity, CapabilityLease, DelegationChain, TrustMetadata (ed25519)

### Current State
- 22/22 gateway packages + identity module pass `go build ./...`, `go vet ./...`, `go test -race ./...`
- 5 execution surfaces: shell, exec, git.push, git.pull, git.fetch, git.checkout
- Policy engine with allow/deny/escalate, dynamic approvals, cryptographic receipts
- Machine identity with ed25519, capability leases, agent registry
- Trust evaluation with anomaly heuristics, shield auto-restriction
- Continuation state machine with orchestrator, stuck-executing recovery
- All stores support file-backed persistence with retention

---

## Phase 65: V1 Hardening & Cleanup

### Objective
Address all remaining risks from Phase 64 checkpoint, remove legacy code, add missing observability, and bring the codebase to production-grade quality.

### Tasks

| # | Task | Files | Tests |
|---|------|-------|-------|
| 65.1 | Remove legacy `ready` state from state machine | continuation/store.go, continuation/file_store.go, continuation/orchestrator.go, handlers/continuations.go, handlers/runtime.go | Update existing tests |
| 65.2 | Add panic recovery in orchestrator executeOne | continuation/orchestrator.go | New test for panic recovery |
| 65.3 | Add executing_breaching to /v1/runtime/health SLA | handlers/runtime.go | runtime_sla_test.go |
| 65.4 | Add comprehensive integration test suite | New: handlers/integration_test.go | 12+ integration tests |
| 65.5 | Run linter, fix all warnings | All .go files | — |
| 65.6 | Add godoc comments to all exported symbols | All packages | — |
| 65.7 | Create benchmarks for critical paths | handlers/benchmark_test.go | — |
| 65.8 | Merge phase-64-v1-polish to main | — | Full suite |

### Exit Criteria
- `ready` state fully removed, zero references
- Panic recovery in orchestrator with test coverage
- Health endpoint surfaces all three breach types
- Integration tests cover full lifecycle: check→escalate→approve→execute→receipt
- `go vet ./...` clean with zero warnings
- All exported symbols documented
- Benchmarks runnable

---

## Phase 66: Identity Integration Deepening

### Objective
Complete the cryptographic identity verification pipeline. Currently the gateway's identity validator only checks structure; wire full ed25519 signature verification and delegation chain validation.

### Tasks

| # | Task | Files | Tests |
|---|------|-------|-------|
| 66.1 | Add `ValidateSignature()` to identity validator calling ovara.identity | identity/validator.go | validator_test.go |
| 66.2 | Add delegation chain cryptographic verification | identity/validator.go | validator_test.go |
| 66.3 | Wire signature verification into evaluator pipeline | evaluator/evaluator.go | evaluator_test.go |
| 66.4 | Add identity verification integration tests with real keys | handlers/integration_test.go | Integration |

### Exit Criteria
- CapabilityLease signatures cryptographically verified
- DelegationChain hash lineage verified
- Invalid signatures rejected at evaluation time
- Full test coverage for all verification paths

---

## Phase 67: Trust-Aware Security (Roadmap Phase 3)

### Objective
Shift from static heuristic scoring to richer trust models: drift detection, trust degradation/recovery, and policy rules that depend on trust state.

### Tasks

| # | Task | Files | Tests |
|---|------|-------|-------|
| 67.1 | Add drift detection (action pattern deviation over time) | trust/drift.go | drift_test.go |
| 67.2 | Add trust degradation/recovery model | trust/degradation.go | degradation_test.go |
| 67.3 | Add trust-dependent policy rules | evaluator/evaluator.go, policy/store.go | evaluator_test.go |
| 67.4 | Add suspicious capability chaining detection | trust/chain_detection.go | chain_detection_test.go |
| 67.5 | Add trust state persistence | trust/state_store.go | state_store_test.go |

### Exit Criteria
- Drift detection identifies anomalous action patterns over time windows
- Trust scores degrade with repeated risky behavior and recover with clean behavior
- Policy can express rules conditioned on trust level
- Suspicious delegation patterns detected and escalated

---

## Phase 68: Production Readiness

### Objective
Final polish: comprehensive documentation, deployment manifests, operational runbooks, and production validation.

### Tasks

| # | Task | Files | Tests |
|---|------|-------|-------|
| 68.1 | Production deployment guide (systemd, Docker) | docs/deployment.md | — |
| 68.2 | Operational runbook (monitoring, alerting, recovery) | docs/operations.md | — |
| 68.3 | Security hardening guide | docs/security/hardening.md | — |
| 68.4 | API reference documentation | docs/api/reference.md | — |
| 68.5 | Final full-suite validation | All | Full suite |
| 68.6 | DELIVERY_REPORT.md | DELIVERY_REPORT.md | — |

### Exit Criteria
- All documentation complete
- All tests passing (`go build`, `go vet`, `go test`, `go test -race`)
- Deployment guide validated
- Project ready for production use

---

## Risk Areas

1. **File store concurrency** — File-backed stores use JSONL append with file locks but may have edge cases under high concurrency. Mitigation: integration tests with concurrent operations.
2. **Identity signature verification** — Currently the gateway model types carry signature bytes but no verification is performed. Full ed25519 verification could introduce latency. Mitigation: benchmark and optimize.
3. **Trust model complexity** — Overly aggressive trust degradation could cause false positives. Mitigation: configurable thresholds with sensible defaults.
4. **Single-binary limitation** — No horizontal scaling. Mitigation: document scaling patterns (multiple instances behind load balancer with shared policy).

## Known Limitations (By Design)

- No distributed coordination (local-first architecture)
- No plugin architecture
- No cloud control plane (Phase 4/5 roadmap items)
- TypeScript/Python SDKs are separate codebases
- No catch-22 circular condition detection
- No GET required_action_fields

## Current File Manifest

- `runtime/gateway/` — 122 Go files (53 source + 62 test + 7 config/docs)
- `identity/` — 14 Go files (7 source + 7 test)
- `examples/` — 9 files (shell scripts, configs, README)
- `docs/` — 60+ documents across 12 directories

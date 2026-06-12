# Phase 78 — Deep Hardening Checkpoint

## Branch
`phase-78-deep-hardening`

## Goal
Apply deep hardening: fix high-severity error handling and security issues,
add OpenTelemetry tracing instrumentation, deploy the trust-server HTTP
service, wire federated client into the gateway evaluator, and add the
portable trust state SDK.

## Deliverables

### 1. OpenTelemetry Tracing Instrumentation (`runtime/gateway/internal/observe/`)
- `tracing.go` — OTel SDK initialization with OTLP exporter
- `spans.go` — span creation helpers for the decision pipeline
- `tracing_test.go` — span emission validation
- Span coverage:
  - `runtime.check` (root span for each check request)
  - `policy.evaluate` (policy rule iteration)
  - `identity.verify` (signature verification)
  - `capability.check` (lease scope check)
  - `trust.compute` (trust score computation)
  - `continuation.execute` (continuation lifecycle)
- Span context propagation through HTTP headers (`traceparent`, `tracestate`)

### 2. Trust Server (`trust/cmd/trust-server/`)
- HTTP service exposing federated trust queries
- Endpoints:
  - `GET /v1/trust/organizations` — list all known organizations
  - `GET /v1/trust/path?source=...&target=...` — compute trust path
  - `GET /v1/trust/federations/:domain` — get federations for a domain
  - `POST /v1/trust/verify-receipt` — verify a cross-org receipt
  - `GET /v1/trust/state/export` — export state as JSON
  - `POST /v1/trust/state/import` — import state from JSON
- Tests in `main_test.go`

### 3. Federated Client (`runtime/gateway/internal/evaluator/federated_client.go`)
- HTTP client for cross-gateway trust queries
- Used when a decision depends on a federated identity
- Caching of trust paths (TTL-based, configurable)
- Graceful degradation when trust-server is unreachable

### 4. Portable Trust State SDK (`trust/internal/state/`)
- `store.go` — file-backed state store with append-only semantics
- `ExportState()` — serialize drift, degradation, chain detection state
- `ImportState()` — restore state from JSON
- Used for backup/restore, cross-instance sync, audit export

### 5. High-Severity Fixes (`1ef2027`)
- **Error handling**: All error returns from `io.Copy` checked; context
  cancellation errors distinguished from real failures
- **Path traversal**: Strict validation of user-supplied paths in all
  file-backed stores
- **Race conditions**: Lock ordering verified in concurrent paths
- **Resource leaks**: `defer Close()` on all open file handles
- **Panic recovery**: Added to all goroutine spawn points in orchestrator

### 6. AppArmor Profile Hardening
- Explicit deny rules for `sys_admin`, `sys_rawio`, `sys_ptrace`,
  `sys_module`, `sys_boot`
- Read-only `/etc`, `/usr`; read-write only `var/data`, `var/log`
- Network: only outbound to configured control plane
- `deny ptrace`, `deny dbus`, `deny mount`, `deny kexec`

## Validation
- All Go modules pass `go test -race ./...` with 0 data races
- All TypeScript modules pass `tsc --noEmit` and `vitest run`
- All Python tests pass
- `golangci-lint` clean on all new files

## Files Changed
- `runtime/gateway/internal/observe/tracing.go` (new)
- `runtime/gateway/internal/observe/spans.go` (new)
- `runtime/gateway/internal/evaluate/federated_client.go` (new)
- `trust/cmd/trust-server/main.go` (new)
- `trust/internal/state/store.go` (extended)
- `security/apparmor/ovara-gateway` (hardened)
- Various error-handling fixes across 8 files

## Next Phase
Phase 79 — Final Completion: code quality, full test coverage, repository
hygiene, documentation updates.

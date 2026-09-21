# Changelog

All notable changes to Ovara are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-21

The OVARA 2.0 security series: the gateway becomes an enforceable execution
boundary — enrolled gateway identity, durable revocation, claim-time
authority verification, and Ed25519-signed receipts.

### Added

- **Gateway trust & enrollment (P2.3.1/P2.3.2)**: Ed25519 gateway keys,
  proof-of-possession admission, durable hash-chained registry, key
  lifecycle (active/rotating/superseded/revoked/destroyed). Unenrolled
  gateways refuse to serve.
- **Durable replay (P2.1)**: request nonces and delegation presentation
  keys consumed durably across restarts.
- **Identity & credential lifecycle (P2.2)**: registered credentials,
  rotation with grace window, revocation, suspend/resume/retire/migrate;
  lifecycle routes are operator-only; queued work of suspended or retired
  subjects never executes.
- **Journal integrity (P2.3.3)**: hash-chained registry journal, corrupt
  journals refuse startup, optional external anchor hooks.
- **Revocation boundary (P2.3.4)**: issuer/delegation/lease revocation,
  claim-time authority recheck over every captured hop, linearizable
  claim/revoke races, fail-closed on unavailable revocation state.
- **Receipt signing (P2.3.5)**: Ed25519 `edsig_v1` signatures over the full
  authoritative decision record; offline `gwctl verify-receipt` using
  registry public material only; historical receipts verify across key
  rotation and revocation.
- **Integration closure (P2.3.6)**: 56-case clean-room integration suite
  proving the composed chain — identity → delegation → lease → policy →
  approval → claim → execution → signed receipt — plus denial matrix,
  crash/SIGKILL durability, and cross-domain isolation.

### Security

- Preserved non-claims: software gateway keys ≠ clone prevention; signed
  receipts ≠ execution truth or global immutable history; trust_epoch ≠
  consensus; revocation ≠ kill-on-revoke for running executions.

## [Unreleased]

### Security

- **Capability lease trust anchor**: lease signatures are now verified against
  a gateway-configured trusted-issuer registry (`trusted_issuers` in
  config.json), never against keys carried in the request. Unsigned leases and
  unknown issuers are rejected.
- **Default decision is escalate**: requests matching no policy rule now
  escalate for approval instead of being allowed by default.
- **Control-plane tenant isolation**: API keys are bound to their
  organization; cross-tenant requests are rejected.
- **Approval service auth**: the standalone approval service now requires a
  bearer token.
- **Receipt storage verification**: real HMAC verification instead of a
  signature-length check.
- **Sandbox fixes**: corrected Docker container-create body so network
  isolation and read-only rootfs actually apply; exec now reports the real
  exit code.
- **Executor hardening**: git `checkout` uses `--` separator (flag injection);
  GitHub executor path-escapes URL segments.
- **SDK verification fixes**: TypeScript ed25519 verification now uses a real
  WebCrypto call; Python `verify_capability_lease`/`verify_agent_identity`
  require a trusted public key parameter instead of self-asserted fields.

### Documentation

- Corrected claims across `docs/` where docs described unimplemented security
  properties (mandatory verification, TLS, RBAC, signed delegation chains,
  eBPF blocking, non-bypassable interception).
- Added `docs/architecture/executor_proxy.md` — the V2 target architecture:
  a credential-starving executor proxy where every side effect transits a
  notarizing chokepoint.

## [1.0.0] - 2026-06-12

### Added

- **Runtime Gateway (Phase 1-65)**: 12 execution surfaces (`shell`, `exec`, `git.push/pull/fetch/checkout`, `github.push/pr/merge/delete_branch`, `ci.trigger`, `shell.sandboxed`) with allow/deny/escalate policy evaluation, HMAC-SHA256 cryptographic receipts, SLA health diagnostics, stuck-executing recovery, and panic recovery.
- **Machine Identity (Phase 66)**: 4 cryptographic primitives — `AgentIdentity` (ed25519), `CapabilityLease` (signed with TTL/depth), `DelegationChain` (SHA-256 hash lineage), `TrustMetadata`. Cryptographic signature verification wired into gateway evaluator.
- **Trust-Aware Security (Phase 67)**: drift detection (sliding-window action pattern analysis), trust degradation (exponential decay + streak acceleration), chain detection (self-delegation, depth, rapid re-delegation), trust-dependent policy rules (`MinTrustScore`, `MinTrustLevel`).
- **Production Hardening (Phase 68)**: deployment guide (systemd, Docker), operations runbook, security hardening profile, full API reference, comprehensive test suite.
- **Cloud Foundation (Phase 69)**: hosted control plane (Fastify + Drizzle ORM + PostgreSQL) with multi-tenant support, gateway enrollment, policy distribution, API key management, revocation APIs.
- **Enrollment Sync (Phase 70)**: cloud enrollment client (ed25519 key generation), policy sync service, cloud heartbeat.
- **Observability Pipeline (Phase 71)** *(assets shipped, not wired)*: OpenTelemetry-compatible span exporter and NATS event streaming code exist in `internal/observe/` but are never instantiated in `server.go`; ClickHouse analytics schema (5 tables, materialized views) shipped under `telemetry/`. See `observability/README.md`.
- **Enterprise Features (Phase 72)**: OIDC + SAML SSO providers, compliance report generator (SOC2, GDPR, audit summaries), audit pipeline.
- **Infrastructure (Phase 73)**: Terraform K8s manifests (control plane 2-replica, gateway HPA 3-20, PostgreSQL; multi-region us-east-1/us-west-2/eu-west-1/ap-southeast-1 layout scaffolded in regions.tf but modules commented out), Docker Compose full stack, Dockerfiles for all services.
- **Federated Trust (Phase 74)**: cross-organization trust graph with DFS path computation, portable ed25519-signed cross-org receipts, federated identity bridging.
- **SDKs (Phase 75)**: TypeScript SDK (`@ovara/sdk`) with 16-method client, retry with exponential backoff, portable verification (18 tests passing). Python SDK (`ovara-sdk`) with async httpx, ed25519 verification (70 tests passing).
- **Production Hardening & Final Validation (Phase 76)**: 0 data races across 30+ Go packages, 100% TS strict mode compliance, 4 docker-compose files, 11 Dockerfiles, 3 GitHub Actions workflows.
- **Integrations**: CrewAI, OpenAI Agents SDK, OpenAI, LangChain, MCP, Browser Automation — all with portable verification.
- **Trust Server (Phase 77)**: HTTP service for federated trust queries, federated client in gateway evaluator, portable trust state SDK with file-backed ExportState/ImportState.
- **OpenTelemetry tracing instrumentation (Phase 78)** *(not wired)*: OTLP-compatible span emission code exists; it is not instantiated by the running gateway.
- **Hardening & Code Quality (Phase 79)**: high-severity error handling fixes, security improvements, code quality improvements (deduplication, entropy), handler tests for all service servers, migration tool tests.
- **Admin Dashboard (apps/admin-dashboard)**: Next.js dashboard with gateway monitoring, policy editor, audit log, organizations, gateways, and settings pages (25 tests).
- **Go CLI (tools/cli)**: 7 integration tests for operator workflows.
- **Migration tool (tools/migration)**: local-to-cloud data transfer with converter, exporter, importer, validator.
- **Benchmark tool (tools/benchmarks)**: load generation, percentile reporting.
- **Security Profiles (security/)**: AppArmor (235 lines), eBPF interceptor (9K C with BPF maps), Seccomp profile (3.4K JSON), Firecracker microVM config.

### Security

- HMAC-SHA256 receipt signing with deterministic action digests
- ed25519 signature verification on all identity artifacts
- SHA-256 hash lineage for delegation chains
- AppArmor mandatory access control profile
- eBPF ring-buffer syscall monitoring
- Seccomp syscall allowlist (~130 syscalls)
- Firecracker microVM hardware isolation

### Performance (Apple M4)

| Operation | Latency |
|-----------|---------|
| Policy-only decision (httptest, in-process) | ~9.7 µs |
| Decision with identity | ~10.7 µs |
| Decision with trust anomaly | ~10.7 µs |
| Full identity+lease decision | ~12.9 µs |
| Throughput (loopback, 50-way) | ~115,000 decisions/sec |
| HMAC-SHA256 sign | ~620 ns |
| HMAC-SHA256 verify | ~650 ns |

### Test Coverage

- **1,200+ test functions** across 30+ packages
- **0 data races** under `go test -race`
- **100+ TypeScript test cases** (Vitest)
- **70 Python test cases** (pytest)

[Unreleased]: https://github.com/SidianLabs/OVARA/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SidianLabs/OVARA/releases/tag/v1.0.0

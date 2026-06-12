# Changelog

All notable changes to Ovara are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-12

### Added

- **Runtime Gateway (Phase 1-65)**: 11 execution surfaces (`shell`, `exec`, `git.push/pull/fetch/checkout`, `github.push/pr/merge/delete_branch`, `ci.trigger`, `shell.sandboxed`) with allow/deny/escalate policy evaluation, HMAC-SHA256 cryptographic receipts, SLA health diagnostics, stuck-executing recovery, and panic recovery.
- **Machine Identity (Phase 66)**: 4 cryptographic primitives — `AgentIdentity` (ed25519), `CapabilityLease` (signed with TTL/depth), `DelegationChain` (SHA-256 hash lineage), `TrustMetadata`. Cryptographic signature verification wired into gateway evaluator.
- **Trust-Aware Security (Phase 67)**: drift detection (sliding-window action pattern analysis), trust degradation (exponential decay + streak acceleration), chain detection (self-delegation, depth, rapid re-delegation), trust-dependent policy rules (`MinTrustScore`, `MinTrustLevel`).
- **Production Hardening (Phase 68)**: deployment guide (systemd, Docker), operations runbook, security hardening profile, full API reference, comprehensive test suite.
- **Cloud Foundation (Phase 69)**: hosted control plane (Fastify + Drizzle ORM + PostgreSQL) with multi-tenant support, gateway enrollment, policy distribution, API key management, revocation APIs.
- **Enrollment Sync (Phase 70)**: cloud enrollment client (ed25519 key generation), policy sync service, cloud heartbeat.
- **Observability Pipeline (Phase 71)**: OpenTelemetry-compatible span exporter, NATS event streaming, ClickHouse analytics schema (5 tables, materialized views), metrics-to-pipeline bridge.
- **Enterprise Features (Phase 72)**: OIDC + SAML SSO providers, compliance report generator (SOC2, GDPR, audit summaries), audit pipeline.
- **Infrastructure (Phase 73)**: Terraform K8s manifests (control plane 2-replica, gateway HPA 3-20, PostgreSQL, multi-region us-east-1/us-west-2/eu-west-1/ap-southeast-1), Docker Compose full stack, Dockerfiles for all services.
- **Federated Trust (Phase 74)**: cross-organization trust graph with DFS path computation, portable ed25519-signed cross-org receipts, federated identity bridging.
- **SDKs (Phase 75)**: TypeScript SDK (`@ovara/sdk`) with 16-method client, retry with exponential backoff, portable verification (18 tests passing). Python SDK (`ovara-sdk`) with async httpx, ed25519 verification (70 tests passing).
- **Production Hardening & Final Validation (Phase 76)**: 0 data races across 30+ Go packages, 100% TS strict mode compliance, 4 docker-compose files, 11 Dockerfiles, 3 GitHub Actions workflows.
- **Integrations**: CrewAI, OpenAI Agents SDK, OpenAI, LangChain, MCP, Browser Automation — all with portable verification.
- **Trust Server (Phase 77)**: HTTP service for federated trust queries, federated client in gateway evaluator, portable trust state SDK with file-backed ExportState/ImportState.
- **OpenTelemetry tracing instrumentation (Phase 78)**: end-to-end trace propagation in runtime gateway with OTLP-compatible span emission.
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
| Policy-only decision | 5,374 ns |
| Decision with identity | 6,126 ns |
| Decision with anomaly | 6,210 ns |
| Full identity+lease decision | 7,669 ns |
| HMAC-SHA256 sign | 598 ns |
| HMAC-SHA256 verify | 614 ns |

### Test Coverage

- **1,200+ test functions** across 30+ packages
- **0 data races** under `go test -race`
- **100+ TypeScript test cases** (Vitest)
- **70 Python test cases** (pytest)

[Unreleased]: https://github.com/SidianLabs/OVARA/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SidianLabs/OVARA/releases/tag/v1.0.0

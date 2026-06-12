# Ovara — Project Plan (Phase 65 → V1.0.0 Production)

**Status:** V1.0.0 DELIVERED
**Current Branch:** `phase-79-final-completion`
**Updated:** 2026-06-12

## Architecture Summary

Ovara is a single-binary Go gateway providing runtime trust infrastructure for
autonomous systems. It intercepts agent actions, validates machine identity
and capability leases, evaluates policy rules, computes trust signals, and
decides allow/deny/escalate — all with cryptographic receipts and full
auditability. Phase 69-76 added a hosted TypeScript cloud control plane,
federated trust, SDKs, framework integrations, and an admin dashboard.

### Active Modules
- `runtime/gateway/` — 152 Go files, 30 packages. The monolith.
- `identity/` — 14 Go files. Machine identity primitives.
- `trust/` — 20 Go files. Federated trust graph + state store.
- `cloud/control-plane/` — 17 TS files. Hosted control plane.
- `enterprise/{sso,compliance}/` — Enterprise add-ons.
- `services/{approval,alerting,observability,receipt-storage,analytics}/` — 5
  Go + 1 TS microservice.
- `tools/{cli,migration,benchmarks}/` — Operator tooling.
- `sdk/{typescript,python}/` — Client SDKs.
- `integrations/{crewai,openai,openai-agents,langchain,mcp,browser-automation}/` —
  Framework integrations.
- `apps/admin-dashboard/` — Next.js admin UI.
- `security/{apparmor,ebpf,sandbox}/` — Security profiles.
- `telemetry/collector/`, `telemetry/schema/` — Telemetry pipeline.
- `infrastructure/terraform/`, `infrastructure/docker-compose.full.yml` —
  K8s manifests and compose.
- `policy/{compiler,adapters}/` — Policy tooling.
- `observability/{grafana,prometheus}/` — Dashboards and alerts.
- `packages/shared-types/` — Cross-language types.

### Current State
- 30/30 gateway packages + identity + trust + 5 services + 3 tools pass
  `go build ./...`, `go vet ./...`, `go test -race ./...`
- 11 execution surfaces: shell, exec, git.push, git.pull, git.fetch,
  git.checkout, github.push, github.pr, github.merge, github.delete_branch,
  ci.trigger, shell.sandboxed (opt-in)
- Policy engine with allow/deny/escalate, dynamic approvals, cryptographic
  receipts, trust-dependent rules
- Machine identity with ed25519, capability leases, agent registry
- Trust evaluation with anomaly heuristics, shield auto-restriction,
  drift detection, degradation model, chain detection
- Federated trust graph with cross-org portable receipts
- 6 framework integrations + TypeScript + Python SDKs
- All stores support file-backed persistence with retention

---

## Phase 65-66: V1 Hardening & Identity Integration

### Phase 65: V1 Hardening & Cleanup
- Remove legacy `ready` state from state machine
- Add panic recovery in orchestrator executeOne
- Add executing_breaching to /v1/runtime/health SLA
- Add comprehensive integration test suite
- Lint, godoc, benchmarks

### Phase 66: Identity Integration Deepening
- Add `ValidateSignature()` to identity validator
- Add delegation chain cryptographic verification
- Wire signature verification into evaluator pipeline
- Add identity verification integration tests with real keys

---

## Phase 67: Trust-Aware Security

- Add drift detection (sliding-window action pattern deviation)
- Add trust degradation/recovery model
- Add trust-dependent policy rules
- Add suspicious capability chaining detection
- Add trust state persistence

---

## Phase 68: Production Readiness

- Production deployment guide (systemd, Docker)
- Operational runbook
- Security hardening guide
- API reference documentation
- Final full-suite validation
- DELIVERY_REPORT.md

---

## Phase 69: Cloud Foundation

- TypeScript + Fastify + Drizzle ORM + PostgreSQL control plane
- 8 route groups: tenants, organizations, gateways, policies, distributions,
  revocations, API keys, gateway enrollment
- API key auth with SHA-256 hashing + scope enforcement
- Zod validation on all write endpoints
- Docker Compose for local development
- 28 tests

---

## Phase 70: Gateway Enrollment & Policy Sync

- Cloud enrollment client (ed25519 key generation)
- Policy sync service (fetches pending distributions)
- Cloud heartbeat with policy version tracking
- 11 tests in `cloud_client_test.go`

---

## Phase 71: Observability Pipeline

- Telemetry pipeline with multi-exporter fan-out
- OTLP span exporter (traceId, spanId, name, attributes, status)
- NATS exporter (subject routing, retry, stats)
- Metrics bridge for periodic snapshot emission
- ClickHouse schema: 5 tables, materialized views, TTL retention
- 9 tests

---

## Phase 72: Enterprise Features

- OIDC provider (PKCE, JWT verification, JWKS, domain whitelist, org mapping)
- SAML provider (auth request, assertion parsing, attribute extraction)
- Compliance report generator (SOC2, GDPR, audit summaries)
- Audit pipeline (ingestion, filtering, querying)
- 11 + 15 = 26 tests

---

## Phase 73: Infrastructure & Deployment

- Terraform K8s manifests: control plane 2-replica, gateway HPA 3-20, PostgreSQL
- Multi-region topology: us-east-1, us-west-2, eu-west-1, ap-southeast-1
- Docker Compose full stack with health checks
- Dockerfiles for all services
- NetworkPolicy isolation, TLS via cert-manager

---

## Phase 74: Federated Trust Network

- TrustGraph: multi-org trust network with DFS path computation
- CrossOrgReceipt: portable ed25519-signed receipts
- Federation lifecycle (establish, revoke, key exchange)
- 17 tests

---

## Phase 75: SDKs & Integration

- TypeScript SDK: 16-method client, retry with exponential backoff, portable
  verification
- Python SDK: async httpx, ed25519 verification with `cryptography` library
- 18 + 70 = 88 tests

---

## Phase 76: Production Hardening & Final Validation

- 0 data races across 30+ Go packages
- 100% TS strict mode compliance
- 11 Dockerfiles, 3 docker-compose files
- 3 GitHub Actions workflows
- All checkpoint docs present

---

## Phase 77: Structure Completion

- Filled out all subdirectories: observability, security, services, policy,
  tools, packages, research
- All modules have functional code (no empty stubs)

---

## Phase 78: Deep Hardening

- High-severity error handling fixes
- Security improvements
- OpenTelemetry tracing instrumentation
- Trust-server HTTP service
- Federated client in gateway evaluator
- Portable trust state SDK

---

## Phase 79: Final Completion

- Code quality improvements (deduplication, entropy, tests)
- Handler tests for all service servers
- Migration tool tests
- Trust-server tests
- Phase checkpoint documentation
- Repository hygiene (LICENSE, CHANGELOG, CONTRIBUTING)

---

## Risk Areas (Resolved)

1. **File store concurrency** — File-backed stores use JSONL append with
   file locks. Resolved with integration tests under concurrent operations.
2. **Identity signature verification** — Cryptographic verification wired
   into evaluator. Resolved with benchmarks showing ~7μs full decision path.
3. **Trust model complexity** — Configurable thresholds with sensible
   defaults. Drift window and decay rate both configurable.
4. **Single-binary limitation** — Documented scaling patterns in
   `docs/deployment.md`.

## Known Limitations (By Design)

- No distributed coordination (local-first architecture)
- No plugin architecture (executors are built-in)
- TypeScript/Python SDKs are separate codebases
- Catch-22 circular condition detection limited to single-file policies
- Trust graph rebuilt from disk on restart (state store persists)

## Current File Manifest

| Directory | Files | Purpose |
|-----------|-------|---------|
| `runtime/gateway/` | 152 Go | Main runtime gateway |
| `identity/` | 14 Go | Machine identity primitives |
| `trust/` | 20 Go | Federated trust graph |
| `cloud/control-plane/` | 17 TS | Hosted control plane |
| `enterprise/sso/` | 3 TS | SSO providers |
| `enterprise/compliance/` | 3 TS | Compliance reports |
| `services/approval/` | 8 Go | Approval workflow service |
| `services/alerting/` | 9 Go | Alerting service |
| `services/observability/` | 9 Go | Observability service |
| `services/receipt-storage/` | 9 Go | Receipt storage service |
| `services/analytics/` | 6 TS | Analytics service |
| `tools/cli/` | 2 Go | Operator CLI |
| `tools/migration/` | 9 Go | Migration tool |
| `tools/benchmarks/` | 5 Go | Benchmark tool |
| `telemetry/collector/` | 5 Go | NATS/ClickHouse collector |
| `telemetry/schema/` | 1 SQL | ClickHouse schema |
| `apps/admin-dashboard/` | 12 TS | Next.js admin UI |
| `sdk/typescript/` | 6 TS | TypeScript SDK |
| `sdk/python/` | 5 Py | Python SDK |
| `integrations/crewai/` | 4 TS | CrewAI integration |
| `integrations/openai-agents/` | 4 TS | OpenAI Agents |
| `integrations/openai/` | 3 TS | OpenAI guard |
| `integrations/langchain/` | 3 TS | LangChain tools |
| `integrations/mcp/` | 2 TS | MCP server |
| `integrations/browser-automation/` | 4 TS | Browser interception |
| `policy/compiler/` | 2 TS | Policy compiler |
| `policy/adapters/` | 3 TS | OPA/Cedar/Custom adapters |
| `packages/shared-types/` | 2 TS | Shared cross-language types |
| `infrastructure/terraform/` | 7 HCL | K8s manifests |
| `security/apparmor/` | 1 profile | AppArmor |
| `security/ebpf/` | 1 C + Makefile | eBPF interceptor |
| `security/sandbox/` | 2 YAML/JSON | Seccomp + Firecracker |
| `observability/grafana/` | 2 JSON | Grafana dashboards |
| `observability/prometheus/` | 1 YAML | Alert rules |

**Total:** 25,332 lines Go source, 35,426 lines Go tests, 7,339 lines TS,
1,393 lines Python, 730 lines Terraform, 20,034 lines Markdown across 185 files.

# Ovara

**Runtime trust infrastructure for autonomous systems.**

Ovara sits on the execution path between an autonomous agent and a consequential
action, deciding whether that action should be **allowed**, **denied**, or
**escalated** for human approval — and producing a cryptographic receipt for
every decision.

The first product is **Ovara Runtime**: a low-latency, single-binary Go gateway
that intercepts machine-driven actions (shell, Git, GitHub, CI/CD) and applies
cryptographically-verified machine identity, capability leases, and trust-aware
policy in microseconds.

```text
┌────────────┐   ┌─────────────────────┐   ┌────────────────────┐
│ AI Agent   │──▶│  Ovara Gateway      │──▶│ Target System      │
│ SDK/Code   │   │  • Identity (ed25519)│   │ shell | git | ci   │
└────────────┘   │  • Capability lease │   └────────────────────┘
                 │  • Policy engine    │            │
                 │  • Trust scoring    │            ▼
                 │  • Receipt (HMAC)   │   ┌────────────────────┐
                 └─────────────────────┘   │ Execution Receipt  │
                                           │ (signed, auditable)│
                                           └────────────────────┘
```

---

## Why Ovara Exists

Cloud IAM, API gateways, workload identity, and observability were built for
humans, deterministic services, predictable control flow, long-lived
credentials, and bounded automation.

**Autonomous systems change the threat model and the execution model.** They
make decisions at runtime, use tools adaptively, operate under delegated
authority, and can drift over long horizons. Existing systems can
authenticate these systems, but they cannot adequately **constrain**,
**explain**, or **revoke** them at the moment of action.

Ovara provides that missing layer.

---

## Product Surface

| Product | Status | Description |
|---------|--------|-------------|
| **Ovara Runtime** | ✅ GA | Single-binary Go gateway: interception, policy evaluation, approvals, execution, receipts |
| **Ovara Identity** | ✅ GA | Machine identity primitives (ed25519) with capability leases and delegation chains |
| **Ovara Observe** | ✅ GA | Action lineage, traces, OTLP/NATS telemetry, ClickHouse analytics |
| **Ovara Shield** | ✅ GA | Anomaly signals, trust degradation, containment hooks |
| **Ovara Cloud** | ✅ GA | Hosted control plane, gateway enrollment, policy distribution, multi-tenant |
| **Ovara Federation** | ✅ GA | Cross-organization trust graph with portable receipts |
| **Ovara SDKs** | ✅ GA | TypeScript (`@ovara/sdk`) and Python (`ovara-sdk`) with portable verification |
| **Ovara Integrations** | ✅ GA | CrewAI, OpenAI Agents, OpenAI, LangChain, MCP, Browser Automation |
| **Ovara Admin** | ✅ GA | Next.js dashboard for gateway monitoring, policy editor, audit log |

---

## What You Get

### 11 Execution Surfaces

`shell` · `exec` · `git.push` · `git.pull` · `git.fetch` · `git.checkout` ·
`github.push` · `github.pr` · `github.merge` · `github.delete_branch` ·
`ci.trigger` · `shell.sandboxed` (opt-in via `OVARA_SANDBOX_ENABLED=true`)

### Cryptographic Identity

- **ed25519** key pairs for `AgentIdentity`
- Signed **CapabilityLease** with TTL and delegation depth
- **SHA-256 hash lineage** for `DelegationChain`
- Cryptographic signature verification **wired into the gateway evaluator**

### Trust-Aware Security

- **Drift detection** — sliding-window action pattern analysis
- **Trust degradation** — exponential decay with streak acceleration
- **Chain detection** — self-delegation, depth, rapid re-delegation
- **Trust-dependent policy rules** — `MinTrustScore`, `MinTrustLevel`

### Cryptographic Receipts

- **HMAC-SHA256** signing with deterministic action digests
- Verifiable payload format (`sig_v1:<hex>`)
- File-backed archival with retention

### Operational Tooling

- Operator bearer-token auth, bulk retry/cancel, unified pagination
- SLA health diagnostics, stuck-executing recovery, panic recovery
- Batch check endpoint (`POST /v1/runtime/batch-check`)
- File-backed stores with configurable retention
- Prometheus metrics, OpenTelemetry traces

### Production Hardening

- AppArmor mandatory access control profile
- eBPF ring-buffer syscall interceptor
- Seccomp syscall allowlist (~130 syscalls)
- Firecracker microVM sandbox config
- Multi-region Terraform K8s manifests
- systemd, Docker, and Docker Compose deployment

---

## Performance (Apple M4)

| Operation | Latency |
|-----------|---------|
| Policy-only decision | 5,374 ns |
| Decision with identity | 6,126 ns |
| Decision with anomaly | 6,210 ns |
| Full identity+lease decision | 7,669 ns |
| Evaluator (no HTTP) | 1,271 ns |
| HMAC-SHA256 sign | 598 ns |
| HMAC-SHA256 verify | 614 ns |
| Decision cache get/put | 38-39 ns |

Sub-10μs decision path — fast enough for inline interception in agent workflows.

---

## Quick Start

### Run the Gateway

```bash
git clone https://github.com/SidianLabs/OVARA.git
cd OVARA/runtime/gateway
go build -o ovara-gateway ./cmd/server
./ovara-gateway                              # uses etc/config.json
OVARA_CONFIG=./etc/config.json ./ovara-gateway
```

The gateway starts on `:8080` with the bundled policy in `etc/`. To issue
your first decision:

```bash
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:git push origin main",
    "agent_identity": { "issuer": "ovara", "subject_id": "agt_001" },
    "environment": "dev"
  }'
```

### Use the TypeScript SDK

```bash
npm install @ovara/sdk
```

```typescript
import { OvaraClient } from '@ovara/sdk';

const client = new OvaraClient({
  baseUrl: 'http://localhost:8080',
  agentId: 'agt_001',
  token: process.env.OVARA_TOKEN,
});

const decision = await client.check({
  action_type: 'shell',
  resource: 'shell:git push origin main',
  environment: 'dev',
});

if (decision.decision === 'allow') { /* proceed */ }
if (decision.decision === 'escalate') { /* request approval */ }
```

### Use the Python SDK

```bash
pip install ovara-sdk
```

```python
from ovara_sdk import OvaraClient

client = OvaraClient(base_url="http://localhost:8080", agent_id="agt_001")
decision = await client.check(
    action_type="shell",
    resource="shell:git push origin main",
    environment="dev",
)
```

### Run the Demos

```bash
cd examples
./start_gateway.sh        # in another terminal
./demo_safe_shell.sh
./demo_approval_flow.sh
./demo_restricted_agent.sh
```

---

## Architecture

```mermaid
flowchart TD
    A["AI Agent / Workflow"] --> B["Ovara Runtime Interceptor"]
    B --> C["Identity Verification (ed25519)"]
    C --> D["Capability Lease Validation"]
    D --> E["Policy Engine"]
    E --> F["Risk + Trust Evaluation"]
    F --> G{"Allow / Deny / Escalate"}
    G -->|Allow| H["Execution Sandbox / Target System"]
    G -->|Escalate| I["Human Approval"]
    H --> J["Observe Pipeline (OTLP/NATS)"]
    I --> J
    J --> K["Execution Receipt + Audit Trail"]
```

### Core Primitives

Everything in Ovara builds around five primitives:

- **`AgentIdentity`** — the stable identity of a machine actor
- **`CapabilityLease`** — a short-lived, scoped delegation of authority
- **`DelegationChain`** — the verifiable lineage of authority transfer
- **`TrustContext`** — the current posture used during authorization
- **`ExecutionReceipt`** — the signed record of a decision and resulting action

---

## Monorepo Structure

```
ovara/
├── apps/admin-dashboard/   # Next.js admin UI
├── cloud/control-plane/    # Hosted control plane (Fastify + Drizzle + PostgreSQL)
├── docs/                   # User-facing documentation
├── enterprise/             # SSO (OIDC/SAML), compliance reports
├── examples/               # Sample configs, demo scripts
├── identity/               # Standalone Go module: ed25519 primitives
├── infrastructure/         # Terraform, Docker Compose
├── integrations/           # CrewAI, OpenAI, LangChain, MCP, browser-automation
├── observability/          # Grafana dashboards, Prometheus alerts
├── packages/               # Cross-language shared types
├── policy/                 # OPA/Cedar adapters, policy compiler
├── research/               # Research notes
├── runtime/gateway/        # The main Go gateway
├── sdk/                    # TypeScript and Python SDKs
├── security/               # AppArmor, eBPF, Seccomp, Firecracker profiles
├── services/               # Microservices (approval, alerting, observability, etc.)
├── telemetry/              # NATS collector, ClickHouse schema
├── tools/                  # CLI, migration tool, benchmark tool
└── trust/                  # Federated trust graph and CLI
```

---

## Delivery Phases

| Phase | Title | Status |
|-------|-------|--------|
| 1 | Runtime interception for shell, GitHub, and CI/CD | ✅ |
| 2 | Machine identity, capability leases, signed provenance | ✅ |
| 3 | Trust-aware authorization, drift detection, anomaly-informed escalation | ✅ |
| 4 | Hosted cloud platform, regional gateways, enterprise policy distribution | ✅ |
| 5 | Federated machine identity and portable trust infrastructure | ✅ |
| 6 | SDKs (TypeScript, Python) and framework integrations | ✅ |
| 7 | Production hardening, observability, observability microservices | ✅ |

See [`docs/build/`](docs/build/) for the per-phase checkpoint documents.

---

## Validation

```bash
# All Go modules: build, vet, test, race
make check

# Specific module
cd runtime/gateway && go test -race -count=1 ./...
cd identity && go test -race -count=1 ./...
cd trust && go test -race -count=1 ./...

# TypeScript modules
cd cloud/control-plane && npm test
cd enterprise/sso && npm test
cd enterprise/compliance && npm test
cd sdk/typescript && npm test
cd apps/admin-dashboard && npm test

# Python SDK
cd sdk/python && pytest
```

**Current state:** 1,200+ test functions across 30+ packages, 0 data races,
100% TS strict mode compliance, 70+ Python test cases.

---

## Documentation Map

- Vision: [docs/vision](docs/vision)
- Product requirements: [docs/prd](docs/prd)
- Architecture: [docs/architecture](docs/architecture)
- API reference: [docs/api](docs/api)
- Security: [docs/security](docs/security)
- Operations: [docs/operations.md](docs/operations.md)
- Deployment: [docs/deployment.md](docs/deployment.md)
- Developer: [docs/developer](docs/developer)
- Research: [docs/research](docs/research)
- RFCs: [docs/rfc](docs/rfc)
- ADRs: [docs/adr](docs/adr)
- Build phases: [docs/build](docs/build)

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community norms,
and [SECURITY.md](SECURITY.md) for vulnerability disclosure.

This project follows strict **test-driven development** for all production
code — write the test first, watch it fail, then write the minimum code
to pass.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 SidianLabs.

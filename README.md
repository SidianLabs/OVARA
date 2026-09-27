# Ovara

Ovara is a runtime trust gateway for AI agents. It sits on the execution
path between an autonomous agent and a consequential action — a shell
command, a git push, an API call — and decides whether that action is
**allowed**, **denied**, or **escalated** to a human approver. Every
decision produces a signed receipt; an executor proxy (a
credential-starving MITM) can carry out approved actions without the
agent ever holding real API keys. It is for engineers running agents
that touch production-adjacent systems who need an enforceable boundary
and an auditable trail — not another advisory wrapper.

```text
┌────────────┐   ┌─────────────────────┐   ┌────────────────────┐
│ AI Agent   │──▶│  Ovara Gateway      │──▶│ Target System      │
│ SDK/Code   │   │  • Identity (ed25519)│   │ shell | git | ci   │
└────────────┘   │  • Capability lease │   └────────────────────┘
                 │  • Policy engine    │            │
                 │  • Trust scoring    │            ▼
                 │  • Receipt signing  │   ┌────────────────────┐
                 └─────────────────────┘   │ Execution Receipt  │
                                           │ (signed, auditable)│
                                           └────────────────────┘
```

## The 60-second mental model

Every consequential action flows through the same pipeline:

1. **Check** — the agent (or the proxy on its behalf) calls
   `POST /v1/runtime/check` with `{action_type, resource, environment}`.
2. **Decide** — the policy engine plus trust context returns
   `allow` / `escalate` / `deny`. Unsigned leases and unknown issuers
   are rejected; the shipped config denies everything until you
   configure tokens.
3. **Approve** (escalated only) — a human or approver-rooted signer
   approves the decision; the approved action can then be claimed.
4. **Execute** — an armed executor (host, sandbox, GitHub, CI) or the
   proxy runs the action. Credentials are injected at the wire; the
   agent never sees them.
5. **Receipt** — every step is recorded as a signed receipt
   (`sig_v1` HMAC always; `edsig_v1` Ed25519 once the gateway has an
   enrolled identity key).
6. **Lineage** — at each authority boundary a signed `lin_v1` bundle
   (receipt + delegation chain + lease + approval) is registered on a
   local transparency ledger, offline-verifiable by a counterparty.
   *Demo-scoped today — see the feature table.*

## Quickstart

Requires Go 1.25+ (and `jq` for the demo scripts). Everything here was
run on this branch.

```bash
# Build the unified CLI (gateway + executor proxy in one binary)
cd proxy && go build -o ovara ./cmd/ovara && cd ..

# Zero-setup proof: allow + deny through the chokepoint, both receipted
./proxy/ovara demo

# Full gateway round trip on throwaway state (~20s):
# check → approval → execution → signed receipt + lineage bundles
make demo

# Cross-domain lineage on real processes (~30s): domain A issues an
# action, domain B verifies the bundle offline, A's gateway key is
# retired, and B's pinned anchor still proves the history
make demo-lineage

# Real deployment directory: keys, config, policy, tokens
./proxy/ovara init mydir
./proxy/ovara run -dir mydir     # gateway :8080, proxy :9443 — Ctrl+C exits cleanly
```

In another terminal, check an action against the gateway:

```bash
curl -s -X POST http://localhost:8080/v1/runtime/check \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"shell","resource":"shell:ls -la","environment":"local"}' | jq .decision
# → "allow"   (try environment=dev for "escalate", production for "deny")
```

Route an agent's HTTPS traffic through the credential-starving proxy:

```bash
export HTTPS_PROXY=http://agent:<agent_token>@localhost:9443
export SSL_CERT_FILE=mydir/var/ca.pem
# keep real keys (GITHUB_TOKEN, OPENAI_API_KEY, ...) in the ovara
# process env — the proxy injects them per proxy.json host bindings
```

Gateway-only alternative (no proxy): `./examples/start_gateway.sh`
boots `go run cmd/server/main.go` under `runtime/gateway/` with the
open-on-loopback demo config — then run `demo_safe_shell.sh`,
`demo_approval_flow.sh`, `demo_restricted_agent.sh`,
`demo_inspection.sh`. See [`examples/README.md`](examples/README.md).

Installer alternative: `curl -sSL https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.sh | sh`
(clones + builds `proxy/cmd/ovara` into `~/.local/bin`; `OVARA_BRANCH` overrides the branch).

> **The proxy is only enforceable with an egress boundary.** Without
> one, a cooperative agent uses it and an uncooperative one routes
> around it. `ovara run --boundary netns` or `--boundary docker`
> (requires root) sets that up — details in
> [`proxy/DEPLOYMENT.md`](proxy/DEPLOYMENT.md). HTTPS only.

## What works, and how honestly

> **Pre-release (v0.x).** The gateway core is real and heavily tested;
> the surrounding ecosystem ranges from working to scaffold to planned.

| Component | What it does | Maturity |
|-----------|--------------|----------|
| Runtime gateway (`runtime/gateway`) | Policy check API, approvals, trust scoring, 12 action types, signed receipts, file-backed stores | **Production-shaped core.** ~10–13µs decisions, 1200+ test functions, adversarial suites |
| Executor proxy (`proxy/`) | MITM HTTPS proxy; gateway-check per request; credential injection at the wire; receipt chain | **Works; enforcement depends on you.** Real MITM + injection; advisory unless `--boundary` locks egress |
| Identity / leases / delegation (`identity/`, `trust/`) | ed25519 `AgentIdentity`, signed `CapabilityLease` vs `trusted_issuers`, `DelegationChain` hashes | **Real crypto, local registry.** No CA/distribution yet |
| Human approvals | Escalate → approve → resume; approver-rooted signed envelopes; dual-root anchoring | **Working**, file-backed |
| Gateway trust & revocation (2.0) | PoP-bound gateway enrollment, durable revocation journal, claim-time authority recheck | **Working**, single-domain local enrollment |
| Action lineage (`lin_v1` + ledger) | Signed bundles at authority boundaries; SCITT-shaped ledger; offline verification | **Demo scope.** Single-signer local file ledger — not a production transparency service |
| Shield (drift/containment) | Sliding-window anomaly signals, trust decay, agent restriction | **Working heuristics**, in-memory/store-backed |
| Observability pipeline | OTLP/NATS → ClickHouse | **Scaffold** — not wired (see `observability/README.md`) |
| Cloud control plane, federation, admin UI, SDKs | Hosted control plane, cross-org trust, Next.js dashboard, TS/Python SDKs | **Alpha/scaffold** — partially implemented |
| Hardening (AppArmor, seccomp, Firecracker, K8s TF) | MAC profile, ~130-syscall allowlist, microVM config, deploy manifests | **Configs present**; multi-region TF scaffolded, not wired |

Honest framing for the enforceable boundary (from the 2.0 security
model): the gateway is enforceable for the actions *it* executes;
client-side interceptors stay cooperative. The physical boundary is the
credential-starving proxy — [`docs/architecture/executor_proxy.md`](docs/architecture/executor_proxy.md).

## Performance (measured on Apple M4 — see `docs/BENCHMARKS.md`)

| Operation | Latency |
|-----------|---------|
| Policy-only decision | ~9.7 µs |
| Decision with identity | ~10.7 µs |
| Full identity+lease decision | ~12.9 µs |
| Evaluator (no HTTP) | ~2.7 µs |
| HMAC-SHA256 sign/verify | ~620/650 ns |

~115k decisions/sec on loopback — fast enough for inline interception.

## Repo map

```
proxy/                  # unified `ovara` CLI + MITM executor proxy
runtime/gateway/        # the gateway (Go) — the core
identity/  trust/       # ed25519 primitives; federated trust graph + CLI
services/               # approval, receipt-storage, alerting, observability
cloud/control-plane/    # hosted control plane (Fastify + Drizzle + PG)
sdk/                    # TypeScript, Python SDKs (install from repo, not published)
integrations/           # CrewAI, OpenAI, LangChain, MCP, browser-automation
examples/               # demo scripts + sample config/policy (start here)
policy/  security/  observability/  telemetry/  infrastructure/  tools/
docs/                   # see docs/INDEX.md — every doc, by the question it answers
```

## Validate

```bash
make build        # go build all 12 modules (fails hard on first error)
make vet          # go vet all modules
make check        # vet + test + build (+ TS targets if deps installed)
cd runtime/gateway && go test -race -count=1 ./internal/idregistry/
```

## Documentation

**[`docs/INDEX.md`](docs/INDEX.md) — every doc, mapped to the question it answers.**

Top-level pointers: [getting started](docs/developer/getting_started.md) ·
[local runtime](docs/developer/local_runtime.md) ·
[runtime API](docs/api/runtime_api.md) ·
[architecture](docs/architecture/) · [operations](docs/operations.md) ·
[deployment](docs/deployment.md) · [roadmap](docs/roadmap.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
and [SECURITY.md](SECURITY.md). Production code here follows strict TDD —
write the test first, watch it fail, write the minimum to pass.

## License

Apache License 2.0 — [LICENSE](LICENSE). Copyright 2026 SidianLabs.

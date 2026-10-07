# Changelog

All notable changes to Ovara are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Focus: make the product usable and understandable for people running coding
agents, and fix correctness bugs found in an in-depth review.

### Security (hardening pass)

- **Default policy no longer lets an agent send data out unapproved.** `GET *`
  and the host-less `POST *git-upload-pack` rule are gone. Reads are allowed only
  from a list of trusted hosts (package registries, code hosts, docs); git
  clone/fetch only from GitHub, GitLab and Bitbucket; any other host pauses for
  approval. A `GET`/`HEAD` that carries a body or a query over 512 bytes is
  escalated even on an allowed host. **Behaviour change:** existing
  `policy.json` files are not rewritten; re-run `ovara init -force` in a scratch
  directory and compare, or add rules for hosts you need.
- **No DNS lookup before policy.** `CONNECT` no longer resolves a host name
  before policy has seen a request for it (a lookup of `<data>.attacker.example`
  is itself a data channel). Names are resolved at dial time; private IP
  literals are still refused immediately.
- Host matching for sensitive-host rules is case- and trailing-dot-insensitive.
- `X-HTTP-Method-Override` and similar headers are no longer forwarded.
- Response scrubbing redacts only secret values (plus the bare token and its
  URL/JSON-escaped spellings), no longer protocol values such as
  `anthropic-version`.
- Proxy hardening: header/idle timeouts, TLS handshake deadline, cap of 64
  requests parked on approval, rate-limited receipts for unauthenticated
  requests, and loopback (`127.0.0.1:9443`) as the default listen address.
  `--boundary` still binds the boundary-facing address. Streamed (SSE)
  responses are flushed as they arrive.
- The proxy CA is never silently regenerated: an existing but unusable CA is an
  error instead of being overwritten.
- **Gateway fails closed.** A configured persistent store (receipts, approvals,
  continuations, executions, events, capabilities) that cannot be opened now
  stops startup. It used to fall back to an empty in-memory store, turning
  tampering or corruption into silent data loss.
- **An approved action is never run unrecorded.** Continuation claim, retry,
  cancel and recover roll back and refuse if the transition cannot be written,
  so a crash cannot make a restart run the same approved action again.
- Journal: a complete final record missing only its newline is terminated
  instead of being merged with the next append. Compaction removes stale temp
  files, and releases the live journal before renaming (needed on Windows).
- Degraded anchor mode no longer anchors an unverified local-ahead tail.
- Decision, approval, continuation, execution and event IDs are full UUIDs; the
  approval action digest is length-prefixed, full SHA-256, and binds environment
  and metadata.
- `ovara doctor` checked the wrong config keys (always warned "memory-mode"); it
  now checks the real ones, warns when no off-host anchor is configured, and
  fails on `fail_open` / `unsafe_no_agent_auth`.
- Release workflow tests the exact tag on Linux, macOS and Windows for both the
  proxy and gateway modules, runs with least-privilege permissions, and attests
  build provenance. `install.sh` no longer turns a failed download into a build
  of `main` (a pinned version is honoured), requires HTTPS, matches checksum
  names exactly, and both installers support `OVARA_VERIFY=1` provenance
  checks; `install.ps1` forces TLS 1.2 and asks before editing PATH.

### Added

- **Prebuilt releases**: pushing a `v*` tag runs `.github/workflows/release.yml`,
  which tests, builds `ovara` for linux/darwin (amd64, arm64) and windows/amd64,
  and publishes archives plus `checksums.txt` as a GitHub release.
  `install.sh` / `install.ps1` download the right archive and refuse it if the
  SHA-256 does not match (source build fallback in install.sh). `ovara version`.
- **Local approval page**: `ovara run` serves `http://127.0.0.1:9090` (link with the
  operator token in the URL fragment), with pending requests (Approve / Deny) and
  integrity-checked recent activity. Loopback-only, Host-checked against DNS
  rebinding, token in a header (no cookies, so no CSRF), not frameable.
  `-ui off` disables it.
- **`ovara watch`, `ovara approvals`, `ovara approve <id>`, `ovara deny <id>`**:
  answer an agent's paused requests from the terminal, in plain English.
- **`ovara env`**: prints the agent environment for bash / PowerShell / cmd: proxy
  URL with the agent token, Ovara's CA for Node / Python / curl / git / OpenSSL,
  and placeholder API keys. (The old instructions omitted the agent token, so
  every request got a 407.)
- **`ovara policy`** explains the rules in plain English (blocked / allowed /
  ask me first), and **`ovara policy test "<METHOD URL>"`** dry-runs a request
  against the live policy and names the rule that decided. The gateway's
  `/v1/policy/simulate` now returns `MatchedRule`.
- **`ovara log`**: what the agent did, one line per request (allowed / approved /
  blocked / timed out), with an offline integrity check of the receipt chain.
- Default policy allows `git clone`/`fetch`/`pull` (a POST to `git-upload-pack`
  that only reads). Pushes still need approval. Verified with a real clone.
- `ovara watch` and `ovara approvals` skip requests the agent already stopped
  waiting for, since approving them would do nothing.
- **A useful default policy from `ovara init`**: reads allowed, writes (git push,
  PRs, deploys, deletes) escalate for human approval, known data-dump sites denied.
- **A narrated `ovara demo`** (allow, pause-and-approve, block, verified
  receipts) with an automated end-to-end test.
- **Windows support**: the gateway and `ovara` now build and run natively on
  Windows (portable file locking, platform-aware permission checks).
- CI: the `proxy` module (the shipped `ovara` binary) is now tested and linted;
  Windows and macOS build/test jobs; Python SDK tests run in CI.
- New README that explains what Ovara is and how strong each mode is; the long
  overview moved to `docs/overview-full.md`.

### Removed

- Disconnected, broken or unsafe modules: `trust/` (unauthenticated federation
  server), `identity/` (unused, incompatible lease format), `telemetry/`,
  `services/analytics`, `packages/`, four scaffold integrations, `infrastructure/`,
  `observability/`. All are recoverable from git history.
- The cloud control plane (`cloud/control-plane`), admin dashboard
  (`apps/admin-dashboard`) and `enterprise/` (SSO, compliance). They could not
  start from their image or talk to the gateway (incompatible rule format, no
  enrollment wiring) and had multi-tenant security holes. See
  `docs/decisions/cloud-control-plane.md`; recoverable from git history.

### Fixed

- **Signed-journal mode: every continuation update failed.** `FileBackedStore.Update`
  wrote to a nil file handle, so finished work stayed "executing" and could be
  retried (a side effect running twice). Now journaled like every other write.
- **The synchronous `POST /v1/continuations/{id}/execute` endpoint skipped the
  claim-time provenance check** that the background executor runs; a forged
  continuation could execute through it. It now runs the same check.
- **Duplicate approvals under concurrent requests** for one decision (two
  approvals, two continuations, the action running twice). Creation is now
  atomic, and a failed continuation write is reported instead of dropped.
- **A key not set in Ovara's environment broke the agent's own credentials**:
  `${GITHUB_TOKEN}` expanded to nothing and the proxy overwrote the agent's working
  header with `Bearer ` (or an empty `x-api-key`, breaking Claude Code subscription
  logins). Such bindings are now skipped with a clear startup message, and `ovara env`
  sets placeholders only for keys Ovara really injects.
- **Credentials could leak to the agent (SEC-0001):** Range requests and
  upstream-encoded bodies slipped past the reflected-credential scrubber. The
  proxy now strips `Accept-Encoding`/`Range` on credentialed requests and refuses
  bodies it cannot scrub.
- **`fail_open` injected real credentials** into traffic that had no policy
  decision. Fail-open traffic is now forwarded without credentials.
- **Receipts signed by a revoked or destroyed gateway key after its
  revocation no longer verify** (`gwctl verify-receipt`, `/v1/receipts/verify`).
  Receipts from before the revocation still verify; backdating by a key holder
  remains the documented key-compromise limit.
- `ovara run --boundary netns` printed a proxy address that did not match the
  one the script configured, and told you to run the agent as root. It now
  prints the right address and runs the agent as your user.

## [0.9.0] - 2026-09-21

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

## Earlier changes (previously a second, duplicate `[Unreleased]` heading)

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

## [0.1.0] - 2026-06-12 (previously tagged v1.0.0 — premature; renumbered)

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

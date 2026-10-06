# OVARA v1 Audit — Phase 0 reconnaissance output

**Date:** 2026-10-06 · **Auditor:** agent (builder role) · **Commit audited:**
`0639bdf` (main at session start) · **Method:** static code reading + full
module test run. No adversarial execution (no container runtime on host —
see `state/HUMAN_ATTENTION.md` A1). Every claim carries an evidence tag.

> Naming note: the brief calls the current code "v1". The repo self-describes
> as OVARA 2.0/2.1 — a security-reviewed iteration with a prior red-team
> pass (`docs/OVARA_2_PHASE0_RECONCILIATION.md`, `security/findings/`). This
> audit treats the current checkout as "v1 = the baseline the rewrite must
> beat" regardless of version label.

---

## 1. Module map

12 Go modules, no `go.work` — each builds independently
`[VERIFIED: find . -name go.mod]`:

| Module | Role |
|---|---|
| `runtime/gateway` | core: HTTP decision API, evaluator, policy, identity, trust, receipts, continuations, anchors, sandbox client, shell+git interceptors |
| `proxy` | executor chokepoint: MITM forward proxy (`cmd/ovara` unified binary: init/run/demo/doctor; `cmd/ovara-proxy`), CA, creds, receipt chain |
| `identity` | identity registry CLI + crypto/store/federation internals |
| `trust` | trust engine service: chain_detection, degradation, drift, graph, receipt, state |
| `services/alerting`, `services/approval`, `services/observability`, `services/receipt-storage` | auxiliary HTTP services |
| `telemetry/collector` | NATS-based collector |
| `tools/benchmarks`, `tools/cli`, `tools/migration` | load generator, CLI, migration tool |

Non-Go: `sdk/typescript`, `sdk/python`; `policy/adapters/{cedar,custom,opa}`
TS adapters and `policy/compiler`; `apps/admin-dashboard`;
`integrations/{mcp,langchain,openai,openai-agents,crewai,browser-automation}`;
`security/ebpf` (C source + hooks.yml spec); `cloud/control-plane`;
`enterprise/{compliance,sso}`.

Code size (Go, excluding `workspace/`): ~40.2k LOC implementation, ~47.4k
LOC test, 353 files `[VERIFIED: find/wc]`.

External deps are small: proxy + telemetry carry the only non-trivial
`require` blocks (uuid, fsnotify, x/sys; nats, nuid, compress, x/crypto);
other modules are essentially stdlib-only `[VERIFIED: go.mod scan]`.

## 2. Action model — the "14 action types"

`ActionType` is a string enum
`[VERIFIED: runtime/gateway/internal/models/action_request.go:8-25]`:
`shell`, `exec`, `git.push`, `git.pull`, `git.fetch`, `git.checkout`,
`git.force_push`, `github.push`, `github.pr`, `github.merge`,
`github.delete_branch`, `ci.deploy`, `ci.build_trigger`, `ci.approval` —
14 values, matching the brief.

`ActionRequest` fields: action_type, resource (string), agent_identity
(issuer/subject/owner/lifecycle/verify_key), capability_lease,
delegation_chain, environment (local|dev|staging|production), metadata
(raw JSON), nonce, issued_at, min_epoch (revocation freshness floor)
`[VERIFIED: action_request.go:36-51]`. `Validate()` requires only
action_type, resource, environment, nonce, issued_at — **identity and
lease are optional at the schema level** `[VERIFIED: action_request.go:108-126]`.

`DecisionResponse`: allow | deny | escalate + reason codes (~30), trust
context, receipt stub, decision_id, approval_id
`[VERIFIED: decision_response.go]`.

Observation O-1: resource is a free-form string; normalization happens at
match time (`policy.MatchResource` canonicalizes URL-shaped resources —
lowercased host, default-port strip, host-label boundary, userinfo/malformed
fail-closed `[VERIFIED: policy/store.go:164-200]`). Non-URL resources
(`shell:...`, `git:local`) get plain glob matching — string-level, not
semantic (no path/symlink canonicalization for shell/fs semantics).
**That is the action-normalization gap v2 must close.**

## 3. Interception — what is enforced vs observed vs cooperative

Three interception surfaces exist:

1. **Executor proxy (enforced at the network layer).**
   `proxy/internal/proxy/proxy.go` — forward proxy with CONNECT MITM.
   Properties `[VERIFIED: proxy.go]`:
   - CONNECT restricted to :443 only (`connectPort443`, default on, :300-303);
   - SSRF guard: resolves destination itself and dials only validated
     public IPs — the dial path re-checks the exact IP dialed, closing the
     DNS-rebind TOCTOU (`dialChecked`, :216-240); mixed public/private
     answers refuse the request;
   - optional client auth via Proxy-Authorization token (`agentToken`,
     constant-time compare, :108-129);
   - every request → gateway `Check`; unknown/malformed decisions deny
     (:489-494); `failOpen` defaults false;
   - `sensitive_hosts` globs force escalate regardless of policy (:455);
   - credential injection on allow, HTTPS only (:511-521); response
     header+body+trailer scrubbing replaces injected secret values with
     `[REDACTED]` (:545-574);
   - every transit receipts into the chain, including CONNECT-layer denials
     (`recordDenied`, :368-372) and an abort-safe deferred record (:431-441);
   - git push gating parses `git-receive-pack` bodies and appends ref names
     to the policy resource (`gitGate`, :427).
   The boundary that makes this a *chokepoint* rather than a library is
   `proxy/scripts/setup-egress-boundary.sh` — host-side netns (veth +
   nftables default-deny) or dedicated docker bridge (no NAT route, ICC
   off), run with CAP_NET_ADMIN outside the agent `[VERIFIED: script
   header comments + tests/redteam/boundary/run.sh]`.

2. **Shell/git interceptors (cooperative — the honest weak point).**
   `runtime/gateway/interceptors/{shell,git}` are Go helpers a caller
   invokes: they ask the gateway, then run `sh -c <cmd>` locally on allow
   `[VERIFIED: interceptors/shell/interceptor.go:124-180]`. They are
   library calls, not enforcement: an agent that execs directly, or uses
   `python -c`, a build tool, a subshell, or any binary besides the wrapped
   entrypoint, never touches them. The README states this plainly:
   "Client-side interceptors remain cooperative — an agent that bypasses
   them is unconstrained" `[VERIFIED: README.md security-model quote]`.
   `shell.Interceptor.WithResource` lets the caller label a command with a
   *different* resource than executed (documented in-code, :97-108) — a
   footgun v2 must delete.
   The git interceptor classifies push/pull/fetch/checkout and force-push;
   other git verbs map to `git.<verb>` — e.g. `git.commit`, `git.clone`
   become ad-hoc types no rule may match → default escalate
   `[VERIFIED: interceptors/git/interceptor.go:63-78]`.

3. **eBPF hooks (audit-only, not wired).** `security/ebpf/` ships a
   tracepoint spec (`hooks.yml`) whose own comments state these hooks
   "CANNOT block or deny" and nothing references them from Go code
   `[VERIFIED: hooks.yml header; rg -ln ebpf --type go = ∅]`.

Observation O-2: **there is no kernel-mediated path between an agent
process and local resources** — filesystem, process spawn, IPC are
unmediated inside the agent environment. v1's enforcement is: network
egress (real) + cooperative call-sites (advisory). Matches brief P1:
complete mediation does not exist for local actions; it exists for egress
only where the boundary was actually deployed.

## 4. Decision pipeline (evaluator)

`Evaluator.evaluate` order `[VERIFIED: evaluator/evaluator.go:188-509]`:

1. schema validation → deny; 2. freshness ±60s → deny; 3. `min_epoch`
revocation-boundary check → deny before consuming the nonce (freshness
floor can't be poisoned by retry, :216-230); 4. nonce consume — durable
replay store or in-mem 5-min map, StorageFailure fails closed (:231-262);
5. shield-restricted → escalate; 6. agent-identity validation → deny;
7. delegation chain: signature vs trusted-issuer registry, chain linkage,
non-amplification, expiry, audience, terminal-subject binding, replay —
then **capability scoping**: request must fall inside terminal hop's
effective actions+scope (:295-321); 8. lease (only if present):
revocation → deny, signature/expiry → deny, **subject binding** to the
authenticated principal (:354-362), scope match → deny; 9. drift detector
→ escalate; 10. chain-pattern detector → escalate; 11. rule evaluation:
deny rules (action then env) → allow rules → escalate rules → **default
escalate** (:612-614); 12. min-trust rules can demote allow → deny;
13. trust-escalate can promote allow → escalate; 14. shield auto-restrict
after 3 risky decisions.

Posture notes:
- Default is **escalate**, not allow — but `policy/validator.go:40` still
  warns "no rules — all actions will be allowed by default": the warning
  text is stale relative to evaluator behavior (minor inconsistency,
  logged as F-audit-1).
- A nil lease is not an error (deliberate, per :323-328) — SEC-0004's
  "leases optional; identity fully self-asserted" remains structurally
  true unless deployment requires leases.
- `trust.NewEvaluator(...)` output is stateful; decisions are
  deterministic only for a fixed trust state (documented in A16 of the
  reconciliation doc).

## 5. Evidence layer

- **Proxy receipt chain** (`proxy/internal/receipts/chain.go`): JSONL,
  `prev_hash` chained, `sig_v1` Ed25519 over a pipe-delimited canonical
  payload; refuses to resume on unparseable tail rather than forking
  (:91-103); offline `VerifyFile` checks linkage + signatures; optional
  periodic anchors (seq+head hash) to file/URL `[VERIFIED]`. **Gaps
  (known, in-repo):** receipt written after upstream completes (C8),
  anchors unsigned/unauthenticated (C2), `verify` accepting
  self-asserted keys (C1), no seq in receipts (C3/C4) — see §8.
- **Gateway receipts**: legacy HMAC-SHA256 `Signer` + `EdSigner`
  (Ed25519, gateway-id/key-id; `VerifySignature` resolves pubkey from a
  registry, never the receipt) `[VERIFIED: receipt/edsigner.go:131-191]`.
- **Sealed files** (`record/sealed.go`): signed whole-file snapshots for
  atomic-rewrite stores (idregistry, capabilities) with file_seq +
  prev_file_sha256 rollback detection.
- **Anchors** (`anchor/`): checkpoint store + peer-cred client for the
  cross-domain lineage work (per recent PRs).
- **Journals**: `OVARA_2.1_JOURNAL_SPEC.md` + continuation provenance gate
  (`continuation/provenance.go`) — claim-time check that a queued
  continuation resolves to a real approved approval record (post-C2
  hardening; docs are explicit that a stolen key still forges the graph —
  honest scoping `[VERIFIED: provenance.go header]`).

## 6. Sandbox executor

`internal/sandbox` talks Docker Engine over the unix socket: creates
containers with CapDrop=ALL, no-new-privileges, default
`NetworkMode=none`, optional ReadonlyRootfs, bounded output (1MiB cap),
timeout via context `[VERIFIED: sandbox.go:98-161]`. `NoopSandbox`
returns an error rather than pretending success — fail-closed default
(:385-410). Docker socket access is flagged in-code as "effectively root
on the host" (:60-64).

## 7. API surface

~80 registered routes under `/v1/` in `pkg/server` + `internal/handlers`:
check/batch-check, approvals (create/approve/deny/resume — single-use,
provenance-checked), continuations (queue/claim/sweep/recover),
capabilities (track/revoke/history), identities (register/rotate/status/
credentials revoke), receipts, admin reconcile/sweep/compact, whoami
`[VERIFIED: mux.HandleFunc scan]`. Approval provenance is resolved against
the decision record at create (`server.go:505` comment). ShellExecutor for
`shell` actions runs `sh -c` **on the gateway host** — the SEC-0016 class;
fixed per the findings register by gating on approval+provenance.

## 8. Known-issue registers (already in repo — the v1 bypass baseline)

Two overlapping registers exist; both feed `state/BYPASSES.md`:

- **`security/findings/` — OVARA-SEC-0001..0021.** 1 CRITICAL + 6-7 HIGH
  + ~10 MEDIUM. 7 marked VERIFIED-fixed in P0.5 (incl. SEC-0016
  self-minted approval → host RCE; SEC-0009 trailer scrub; SEC-0008
  unauthenticated credentialed relay → `agent_token` exists now). The
  confirmed-unfixed set is the substance: self-asserted identity (SEC-0019),
  self-asserted verifier pubkey (SEC-0002), tail-truncation/unsigned
  anchors (SEC-0003), flat bearer-token root (SEC-0018), policy takeover
  via load paths (SEC-0020), /proc visibility in netns mode (SEC-0007),
  DNS-tunneling residual (SEC-0015), non-proxied execution paths
  (SEC-0012), approval not request-bound (SEC-0014), cosmetic nonce
  replay protection (SEC-0021).
- **`docs/OVARA_2_PHASE0_RECONCILIATION.md`** — ROADMAP items: chain_hash
  canonical mismatch (fail-closed liveness bug), HMAC receipt field
  subset (approval_id unsigned), verify --pubkey requirement, signed+
  authenticated anchors, seq+key_id monotonicity, policy watch-reload
  privesc (A5), approval-request-hash binding (A4), execution-identity
  token at proxy listener (A2/P1b), CA+receipt+creds keys co-located in
  one process (A6 — accepted risk), capability-drop verification (N4),
  no rate/concurrency limits (A8/N7 → self-DoS, escalate-flood), missing
  config → open defaults (P3b), leases optional (P4), receipt-silence
  detection (A10), deny-by-default resolver (N6), cgroup eBPF egress
  (N9), IPv6 matrix (N2), `ovara doctor` (P9 — now present in
  `proxy/cmd/ovara/doctor.go`).

## 9. Test inventory and results (2026-10-06 run)

Command per module: `go test -race -count=1 ./...` `[VERIFIED:
/tmp run — output captured in state/logs]`:

| Module | Result |
|---|---|
| identity, trust, proxy, services/* (4), telemetry/collector, tools/* (3) | **all PASS** |
| runtime/gateway | **all PASS** (incl. tests/integration, tests/load) |

Not run (blocked — A1): `tests/boundary/{netns,docker}_test.sh`,
`tests/redteam/boundary/run.sh` (need Linux + root + docker),
`tests/e2e/*_harness.py` (need a deployed gateway), sdk/typescript vitest
and sdk/python pytest (deps not installed yet — queued in TASKS).
`ovara demo` (self-contained) not yet run — queued.

E2E harness inventory: 10 Python harnesses in tests/e2e keyed to phases
(p21-p236, rc1, final_review) `[VERIFIED: ls]`.

## 10. External integration status (what the repos actually are)

- **MAP (micro-agent-protocol)**: TypeScript reference impl
  `@sidianlabs/map` — policy check → allow/deny/approval + signed
  receipts; "developer preview" per its README. **No code-level
  integration in OVARA Go code** `[VERIFIED: rg finds no map/proto refs]`.
  Receipt formats are parallel inventions; v2 must reconcile rather than
  silently diverge (brief requires MAP integration or documented deltas).
- **POLICY.md**: separate spec + TS engine — Markdown+YAML negative-
  capability manifest (`capability`/`action`/`condition`/`reason`).
  **The Go gateway does not consume it** — its rule store is its own JSON
  shape `[VERIFIED: policy/store.go vs repos/POLICY.md format]`. Compiling
  POLICY.md → v2 policy IR is a Phase 1 spec item.
- **DASH**: Rust vector DB — no references in OVARA code; brief positions
  it as optional evidence index (must stay out of integrity TCB).
- **Sidian** (editor): cloned for context; ACP integration is a Phase-4+
  interception surface item.

## 11. v1 verdict for Phase 0

What v1 already is: a seriously hardened **network-egress boundary** +
decision API — MITM proxy with real TOCTOU-safe SSRF guards, credential
injection with reflection scrubbing, hash-chained signed receipts,
enrolled identity, revocation epochs, single-use approvals, continuations,
docker sandbox executor, default-escalate posture — plus two in-repo
security-review passes with honest residual documentation.

What v1 is **not** (the rewrite rationale, all evidenced above):
1. Complete mediation — local actions (fs, exec, IPC) are unmediated;
   shell/git interceptors are cooperative call-sites.
2. Signed request/execution identity at the interception edge —
   ActionRequests are unsigned; identity/leases optional at schema level.
3. Tamper-evidence that survives its own host — anchors unsigned and
   co-located; verify accepts self-asserted keys; no seq monotonicity.
4. POLICY.md/MAP compatibility — parallel formats, no bridge.
5. Fail-closed config posture — missing config → open defaults (P3b,
   SEC-0017/0018 residual).
6. Rate/concurrency bounds — escalate-flood/self-DoS unbounded (A8/N7).
7. Separation of CA/receipt/cred keys — co-resident in one process (A6).

Every item here is self-acknowledged in the repo's own findings — the v2
program's job is to close them systematically and *prove* closure under
adversarial test, not just assert it.

# OVARA 2.0 — P0.5 CRITICAL SECURITY REMEDIATION REPORT

Scope: the seven authorization/trust-boundary findings from the Phase-0
clean-room audit. Nothing else was touched — no receipt v2, anchoring,
eBPF, observability, dashboard, Firecracker, or Kubernetes work.

Baseline: `docs/OVARA_2_P05_BASELINE.md` (frozen at
`7fc1b685463efc7828a34c5a1ff697c2a4040aa2`, exploit re-confirmed before
any change).

---

## SEC-0016 — Self-minted approval → arbitrary `sh -c` on gateway host (CRITICAL)

**Original vulnerability.** `POST /v1/approval/create` trusted
caller-supplied `decision_id`, `action_type`, `resource`, `agent_id`, and
`environment`. Any caller could fabricate an approval for an action the
policy engine never evaluated, self-approve it with a caller-chosen
`resolved_by`, and the continuation orchestrator executed `sh -c` on the
gateway host (always-registered host executors). Live PoC wrote
`/tmp/cleanroom-pwn.txt` in ~3s; replay wrote `P05-REPRO`.

**Root cause.** No provenance: approval creation did not consult the
server-side decision record. No binding: the continuation was built from
caller JSON. No role separation: one flat token could request AND
resolve. No executor gate: `shell`/`exec`/`git.*` were registered on
every boot.

**Fix (three layers).**
1. *Provenance* — the decision cache now retains the original
   `ActionRequest` alongside the `DecisionResponse`;
   `ApprovalHandler.SetDecisionLookup(h.LookupDecision)` wires it.
   `handleCreate` requires the ID to exist AND to have escalated;
   unknown/fabricated IDs → 404 + `security.violation` event.
2. *Binding* — the approval + continuation are rebuilt entirely from the
   server-recorded request. `request_hash` (receipt ActionDigest) and
   `policy_version` ride the approval and continuation metadata.
   Caller-supplied divergent action/resource/environment/agent → 400 +
   security event.
3. *Execution* — `shell`/`exec`/`git.push|pull|fetch|checkout` register
   only when `enable_host_executors=true`; `POST /v1/approval/{id}/approve|deny|resume`
   and every `/v1/continuations/*` route require an operator-scope token;
   `resolved_by` = authenticated principal (`operator:<label>`), the
   caller label is a display suffix only.

**Security invariant.** A caller cannot manufacture, rebind, or resolve
an approval for an action Ovara did not generate and escalate; and no
API path reaches a host executor by default.

**Regression tests.** `runtime/gateway/internal/handlers/sec0016_regression_test.go`:
fabricated ID → 404; real escalated decision + cross-action/
cross-resource/cross-agent/cross-environment divergence → 400;
non-escalated decision → 409; full create→approve→execute chain fails
closed at `no executor registered`; nil lookup → 404.

**Live replay.** Original PoC: no-auth → 401; agent token → 404;
operator token → 404; `/tmp/p05-pwn.txt` never created. Mutated chain
(real escalated shell decision): agent self-approve → 403;
operator approve → `resolved_by: operator:oncall`; execute →
`no executor registered for action type: shell`.

---

## SEC-0017 — Shipped/default config open on 0.0.0.0 with no auth (CRITICAL)

**Root cause.** `config.Load` returned `Default(), nil` on any read
error; `Default()` had no `listen_addr` (→ all interfaces) and
`auth_enabled=false`; shipped `etc/*.json` mirrored that posture.

**Fix.** `Load` fails on missing/unreadable/malformed files.
`Config.ValidateStartup` runs before bind: `auth_enabled=false` on an
empty or non-loopback bind is refused unless `unsafe_no_auth=true`;
loopback no-auth remains a legitimate dev mode. Shipped configs bind
`127.0.0.1` + `auth_enabled=true`. Auth enabled with zero tokens →
middleware denies everything (503, fail closed). Initial `policy_file`
load failure is now fatal (a bad file can no longer silently become the
built-in default policy). `ovara init` mints real tokens.

**Regression tests.** `runtime/gateway/internal/config/sec0017_test.go`:
missing config → error; malformed → error; no-auth × {"", 0.0.0.0,
192.168.x, 10.x, 172.16.x, ::} → refused; loopback forms → allowed;
unsafe flag → allowed; auth+non-loopback → allowed.

**Live replay.** `ovara run` with missing config.json → fatal;
malformed → fatal; `{"listen_addr":"0.0.0.0","auth_enabled":false}` →
refused with the unsafe_no_auth hint.

---

## SEC-0018 — Flat bearer token = gateway root (HIGH)

**Root cause.** One `operator_tokens` list authorized every route;
the proxy held that token — it could approve its own escalations.

**Fix.** Two domains: `operator_tokens` (gateway-root) and
`agent_tokens`. Agent scope is an allowlist of exactly what the executor
proxy calls: `POST /v1/runtime/check`, `/v1/runtime/batch-check`,
`/v1/approval/create`, `GET /v1/approval/{id}` (excluding `/pending`).
Everything else — including all mutating routes, all reads of events/
receipts/audit/executions/capabilities/policy, and runtime introspection —
is operator-only. New routes default to operator (fail-safe).
`auth.Principal` stamps the authenticated role into request context;
`resolved_by` is derived from it. `ovara init` mints three distinct
credentials: operator (gateway API), agent (proxy→gateway), proxy client
(agent→proxy `Proxy-Authorization`).

**Regression tests.** `runtime/gateway/internal/auth/roles_test.go`:
agent allowed on the 4 endpoint forms; agent denied (403) on a
39-endpoint operator matrix covering approval resolution, continuations,
executions, policy mutation, admin, shield, capabilities, exports, and
runtime introspection; operator allowed everywhere; principal stamping.

---

## SEC-0020 — Unauthenticated policy takeover (HIGH)

**Root cause.** In open mode every policy mutation and admin route was
reachable by anyone who could dial the gateway; the flat token made the
same true in authed mode.

**Fix.** Under the agent allowlist, `/v1/policy/candidate/*`,
`/v1/policy/rollback`, `/v1/policy/restore`, `/v1/admin/*`,
`/v1/shield/*`, `/v1/capabilities/*`, `/v1/continuations/*`,
`/v1/executions*`, and every audit/events/receipts export are
operator-only. Unauthenticated exposure is prevented by SEC-0017.

**Regression tests.** `roles_test.go` operator-denied matrix (policy
rows explicitly). Live replay: agent token `candidate/load` → 403;
no-auth → 401.

---

## SEC-0005 — `resource` dropped on every production load path (HIGH)

**Root cause.** Three rule representations: `LoadStoreFromFile`'s
`fileRule` and the handlers' duplicate `filePolicyLite` lacked the
`resource` field; only dead-code `LoadStoreFromConfig` preserved it.

**Fix.** One canonical parser: `policy.ParseStore` — `json.Decoder` +
`DisallowUnknownFields` into the shared `Rule` struct (which gained
`conditions` and `description` so nothing legitimate is dropped).
`fileRule` is now a type alias. `LoadStoreFromFile`,
`handlers.parsePolicyJSON` (candidate load/promote/simulate/validate)
all route through `ParseStore`. Unknown fields are rejected, never
silently dropped.

**Regression tests.** `policy/loadpaths_test.go` (the audit's
deliberately-failing test — now passes), `canonical_test.go`,
`TestLoadStoreFromFile_PreservesResource`. Live replay: a
resource-scoped candidate policy constrained `/v1/policy/simulate`.

---

## SEC-0010 — Raw-substring resource matcher (HIGH)

**Root cause.** Glob over the rendered string: `api.github.com.evil.com`,
`api.github.com@evil.com`, case, `:443`, and port mismatches all slipped
or broke matching.

**Fix.** `MatchResource` canonicalizes `METHOD scheme://host[:port]/path`
resources: lowercase host+method, strip trailing dot, normalize default
ports (`:443` on https ≡ no port), reject userinfo, host-boundary
semantics (literal authority = exact host only; `*` in the pattern
authority enables subdomain matching), IP literals never match hostname
patterns. Non-URL resources (`shell:`, `org/repo`) keep glob semantics.
Proxy `redactURL` now strips userinfo so credentials can't reach
receipts or the policy string.

**Regression tests.** `policy/canonical_test.go` — 40+-case matrix:
suffix host, embedded host in path, userinfo both directions, wrong
port, prefix host, lookalike, IPv4/IPv6 literals, method case, scheme
mismatch, malformed inputs, empty pattern compat, legacy globs.
Live replay: `api.github.com.evil.com` → escalate; `:443` → allow;
`api.github.com@evil.com` → escalate; `API.GITHUB.COM` → allow.

---

## SEC-0008 — Unauthenticated credentialed proxy on 0.0.0.0 (HIGH)

**Root cause.** The proxy listened on `:9443` (all interfaces) and
required no client credential — anyone who could reach it got injected
credentials.

**Fix.** `agent_token` in proxy.json: clients authenticate via
`Proxy-Authorization` (Basic password or Bearer — what tools send for
`http://agent:TOKEN@proxy:9443`), constant-time compared. Unauthenticated
requests get 407 + a deny receipt — before reaching policy evaluation.
Startup refuses an all-interfaces bind with no `agent_token` unless
`unsafe_no_agent_auth=true`. Shipped proxy.json binds 127.0.0.1.
`ovara init` mints the proxy token; the boundary script picks it up from
proxy.json and emits credentialed proxy URLs.

**Regression tests.** `proxy/internal/proxy/sec0008_test.go` (no header,
wrong basic, wrong bearer, empty basic → 407; basic + bearer → 200;
unauth attempt receipted) and `proxy/internal/config/sec0008_test.go`
(`:9443`, `0.0.0.0:9443`, `[::]:9443` without token → refused; unsafe
flag → starts; token → starts; specific binds → allowed).

**Live replay.** `--proxy http://127.0.0.1:19443` → `407 Proxy
Authentication Required` on CONNECT and plain-HTTP; wrong token → 407;
`agent:TOKEN@` → 200.

---

## Exact files changed

Gateway:
- `runtime/gateway/internal/auth/middleware.go` — roles, agent allowlist, principal context
- `runtime/gateway/internal/config/config.go` — fail-closed Load, ValidateStartup, AgentTokens/UnsafeNoAuth/EnableHostExecutors
- `runtime/gateway/internal/handlers/approval.go` — provenance, binding, derived resolved_by, security events
- `runtime/gateway/internal/handlers/runtime.go` — decision cache stores request; LookupDecision
- `runtime/gateway/internal/handlers/policy.go` — parsePolicyJSON → ParseStore
- `runtime/gateway/internal/approval/models.go` — RequestHash, PolicyVersion
- `runtime/gateway/internal/policy/file_store.go` — ParseStore canonical parser; fileRule → alias
- `runtime/gateway/internal/policy/store.go` — canonical MatchResource; Rule gains conditions/description
- `runtime/gateway/internal/events/store.go` — EventTypeSecurityViolation
- `runtime/gateway/pkg/server/server.go` — lookup wiring, host-executor gate, role middleware, fatal policy-load, auth logging
- `runtime/gateway/etc/config.json`, `etc/sample_config.json` — 127.0.0.1 + auth + token fields
- tests: `auth/roles_test.go`, `config/sec0017_test.go`, `handlers/sec0016_regression_test.go`, `policy/canonical_test.go`, `policy/loadpaths_test.go` (+ updated cache/benchmark/integration test call sites)

Proxy:
- `proxy/internal/config/config.go` — agent_token, unsafe_no_agent_auth, validateClientAuth
- `proxy/internal/proxy/proxy.go` — authorized() + 407 gate + userinfo strip
- `proxy/cmd/ovara/main.go` — three-token init, SetClientAuth, boundary wiring, proxy URL userinfo
- `proxy/cmd/ovara-proxy/main.go` — SetClientAuth + startup log
- `proxy/etc/proxy.json` — 127.0.0.1 bind
- `proxy/scripts/setup-egress-boundary.sh` — --agent-token / proxy.json pickup / credentialed URLs
- tests: `proxy/internal/proxy/sec0008_test.go`, `proxy/internal/config/sec0008_test.go`

Docs/findings: `docs/OVARA_2_P05_BASELINE.md`, this report,
`security/findings/OVARA-SEC-{0005,0008,0010,0016,0017,0018,0020}.md` → VERIFIED.

## Tests executed

- `go test ./...` gateway module — all packages pass
- `go test -race ./...` gateway module — all pass (incl. continuation race tests)
- `go test -race ./...` proxy module — all pass
- `go vet ./...` both modules — clean
- Clean-room replay on a fresh `ovara init` deployment (gateway 18082, proxy 19443)

## Reproduction commands

```bash
# regression suites
cd runtime/gateway && go test ./internal/handlers/ -run SEC0016 -v
go test ./internal/auth/ ./internal/config/ ./internal/policy/ -v
cd proxy && go test ./internal/proxy/ -run ClientAuth -v && go test ./internal/config/

# live replay
/tmp/ovara init /tmp/p05-replay && /tmp/ovara run -dir /tmp/p05-replay &
# original PoC — must NOT create /tmp/p05-pwn.txt
curl -X POST localhost:18082/v1/approval/create -d '{"decision_id":"dec_x","action_type":"shell","resource":"shell:echo PWNED>/tmp/p05-pwn.txt"}'
# → 401 without token; 404 fabricated with any token; 403 agent self-approve; no shell executor
```

## Remaining risks (not P0.5 scope)

- Approval↔request binding uses the receipt ActionDigest (16-hex-char
  truncated SHA-256 over action+resource+agent+lease). Provenance rests
  on the decision cache, not on this digest; full canonical request-hash
  verification at execution is P1 receipt work (SEC-0019).
- `GET /v1/approval/{id}` is agent-readable — approval IDs are
  unguessable but an agent can poll any known ID. Ownership-scoping is P1.
- Open mode (`auth_enabled=false` + `unsafe_no_auth` or loopback) has
  no role separation — acceptable for dev; documented.
- No tenant model exists (single-tenant gateway); cross-tenant
  substitution is N/A by construction.
- SEC-0001 (gzip/encoded scrub leaks), SEC-0002 (evidence
  self-authentication), SEC-0003/0004/0006/0007/0009/0011–0015/0019/0021
  remain OPEN — deferred to P1 per scope.
- SEC-0004 cluster (red-team B): self-asserted `agent_identity.subject_id`
  enables cross-agent containment poisoning/evasion; approval GET lacks
  ownership checks; batch-check receipt parity; self-asserted delegation
  chains; issuer keys in deployment dirs; lease↔subject binding. All P1.
- Policy glob footgun (red-team C V4): resource patterns WITHOUT `://`
  are plain globs — `*api.github.com/*` matches the host string inside a
  path (`https://evil.com/api.github.com/x`). Documented behavior;
  operators must write full URL-shaped patterns for host scoping.
- Dead-pattern footguns (fail-closed direction): `*HTTPS://…`,
  `*https://api.github.com:443/*`, `*https://api.github.com` (no `*`)
  silently never match — validator warnings are a P1 nicety.

## P1 readiness

All seven P0.5 findings are VERIFIED with regression tests AND live
clean-room replay, plus five additional red-team-discovered bugs fixed
and verified in the same manner.

## Independent red-team results

Five independent attackers were given the post-fix codebase and live
deployment with no details of the fixes. Results:

| Reviewer | Scope | Verdict | Findings |
|---|---|---|---|
| A | approval→RCE | **PASS** | RCE dead at two independent layers (provenance + executor gate) |
| B | authz confusion | PASS w/ 1 fix | duplicate approvals per decision → double continuations (fixed); agent-identity self-assertion issues → SEC-0004, P1 scope |
| C | policy bypass | found 4 bugs | V1 space-truncation, V2 `resource:null`, V3 dup keys, V5 dead git-ref rules — **all fixed**; host matcher held against ~60 evasion variants |
| D | config/startup | found 1 bug | `[::0]`/`[0::]`/`[::ffff:0.0.0.0]` unspecified-addr spellings bypassed proxy token requirement — **fixed** |
| E | executor reach | **PASS** | no API path to executor registration; both execute sites fail closed |

### Reviewer C findings and fixes (policy trust surface)

- **V1 space-truncation** (`store.go`): a resource like
  `https://evil.com/?x= https://api.github.com/` split at the first
  space and authorized only the tail — `allow` minted for a claim whose
  destination was evil.com. Reachable by agent tokens via
  `/v1/runtime/check`. **Fix:** the pre-space segment must be a bare
  method token (letters only); a post-URL segment must be a strict
  `refs/`-prefixed git ref list — anything else fails closed.
  Verified live: all crafted forms now escalate.
- **V2 `"resource": null`** silently decoded to `""` → global allow.
  **Fix:** `parseFilePolicyStrict` token-scans every rule and rejects
  `null` on `resource` with an explicit error. Verified live.
- **V3 duplicate `"resource"` keys** last-wins silently overrode scope
  (`{"resource":"*https://api.github.com/*","resource":""}` → global
  allow). **Fix:** the same scan rejects any duplicate key. Verified
  live.
- **V5 git ref-scoped rules were dead**: the proxy appends
  `" refs/heads/x"` after the URL; canonicalization mangled it so
  `*git-receive-pack refs/heads/prod*` could never match (deny-bypass
  for the git gate). **Fix:** the ref suffix is preserved verbatim in
  the canonical string. Covered by regression tests.
- **`/v1/policy/validate` inconsistency**: used non-strict
  `json.Unmarshal`. **Fix:** `ValidatePolicyData` now shares
  `parseFilePolicyStrict`.
- **`LoadStoreFromConfig`** silently dropped non-string `resource`
  (latent global-allow footgun, zero callers). **Fix:** deleted.

### Reviewer D finding and fix (SEC-0008 extension)

- `validateClientAuth` compared literal strings for unspecified binds;
  `[::0]`, `[0::]`, `[0:0:0:0:0:0:0:0]`, `[::ffff:0.0.0.0]` bypassed the
  agent-token requirement. **Fix:** `net.SplitHostPort` + `net.ParseIP`
  + `IsUnspecified()`. Regression test covers 11 spellings.

### Reviewer B finding and fix (SEC-0016 extension)

- Multiple approvals could be created for one decision → multiple
  queued continuations → double execution. **Fix:** approval creation
  is idempotent per `decision_id` (pending/approved returns existing;
  denied returns conflict). Regression test confirms same approval ID.
- B's other breaks chain from self-asserted `agent_identity` — tracked
  under SEC-0004, P1 scope (documented below).

## Final verdict

P0.5 exit criteria: all seven findings VERIFIED (regression test +
live replay + independent attack). Red-team uncovered five additional
in-scope bugs; all five fixed and verified. Remaining breaks require
capabilities documented as P1 scope (agent-identity authenticity,
approval ownership, receipt v2).

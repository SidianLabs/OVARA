# OVARA-SEC-0016 — Self-minted approval → arbitrary `sh -c` on the gateway host (unauthenticated RCE in open deployments)

**Severity:** CRITICAL
**Component:** runtime/gateway/internal/handlers/approval.go:55-99,
continuation orchestrator, execution/store.go ShellExecutor,
pkg/server/server.go:386-405
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Reproduction (verified live, ~3s end-to-end)
```
POST /v1/approval/create
  {"decision_id":"dec_nonexistent_123","action_type":"shell",
   "resource":"shell:echo PWNED > /tmp/cleanroom-pwn.txt",
   "agent_id":"attacker","environment":"local"}
  → {"approval_id":"apr_…","status":"pending"}
POST /v1/approval/apr_…/approve {"resolved_by":"attacker-self"}
  → {"status":"approved"}
~2s later orchestrator claims the queued continuation →
  sh -c runs on the gateway host → /tmp/cleanroom-pwn.txt exists.
```
Equivalent synchronous path: `POST /v1/continuations/{id}/execute`
returns stdout/stderr directly.

## Root cause
- `handleCreate` never validates `decision_id` against the decision
  cache — any string is accepted; `resource`, `agent_id`, trust fields
  are all caller-supplied with no server-side recomputation.
- `resolve` accepts caller-asserted `resolved_by`.
- `ShellExecutor` for action type `shell` is registered
  UNCONDITIONALLY (separate from the gated `shell.sandboxed` Docker
  backend) — plus always-on `exec:` and `git:` host executors (git
  push/fetch against arbitrary local repo paths under gateway creds).
- No requester/approver separation (see SEC-0018).

## Preconditions / reachability
- Open deployments (shipped `etc/config.json`, `sample_config.json`,
  standalone binary): **unauthenticated remote RCE** — the flat gate
  doesn't exist (SEC-0017).
- Hardened `ovara init` deployments: any holder of the single operator
  token — including the proxy itself (`gateway_token` in proxy.json) —
  is gateway-root. Agents are blocked from the gateway by network
  isolation + loopback binding only; any local/co-located process with
  token access (cf. SEC-0007 procfs exposure) reaches it.

## Security impact
Full host compromise under gateway privileges: operator tokens,
`receipt_signing_key`, `github_token`/`ci_token` bindings, docker.sock
(=host root when sandbox enabled). The "human approval" boundary does
not exist as implemented — it is "whoever can POST".

## Proposed fix
1. `approval/create` must require a `decision_id` present in the
   decision cache AND derive action_type/resource/environment/agent
   from the stored `ActionRequest` — reject caller divergence; hash-
   bind (SEC-0014 fix subsumes the binding half).
2. Remove or gate the host `shell`/`exec`/`git` executors — default
   deny registration; require explicit config + operator role.
3. Scoped roles (SEC-0018): `approval create` = agent role;
   `approve`/`deny`/executors = operator role.

## Regression test
`POST /v1/approval/create` with fabricated decision_id → 4xx; approve
with agent-scope token → 403; `shell:` continuation never reaches a
host executor unless explicitly enabled.

## Residual risk
Legitimate shell-automation deployments need an executor allowlist +
per-resource approval pinning — design work, not just a guard.


## Remediation (P0.5 — VERIFIED)

Three-layer fix. (1) Provenance: `/v1/approval/create` requires a decision the
policy engine actually produced and escalated — the decision cache now retains
the original request; unknown/fabricated IDs → 404 + security event.
(2) Binding: action/resource/environment/agent/trust/policy_version/
request_hash are derived from the server-recorded request; caller-supplied
divergences → 400 + security event. (3) Execution: shell/exec/git.* host
executors are not registered unless `enable_host_executors=true`; approval
resolution requires an operator-scope token; `resolved_by` derives from the
authenticated credential.

Regression tests: `handlers/sec0016_regression_test.go` (full PoC chain,
fabricated ID, cross-action/resource/agent/environment divergence,
non-escalated decision, nil-lookup fail-closed, no-executor execute).
Live replay: original PoC dead at auth, fabricate, approve, and execute stages;
/tmp/p05-pwn.txt never created.

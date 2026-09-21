# OVARA 2.0 — P1 Implementation Plan

Plan only — no implementation in this document. Ordered by audit-severity
dependency: policy/trust fixes first (they gate everything else), then
evidence, then hardening. Each item: current state → architecture →
files → invariant → plan → tests → red-team → rollback.

Prerequisite (pre-P1, blocking): the clean-room audit found Phase-0
fixes that are INCOMPLETE — SEC-0005 (resource field dead on all load
paths), SEC-0010 (matcher unsafe), SEC-0001/0009 (scrub surfaces),
SEC-0002/0003 (evidence). These are remediations of Phase-0 scope, not
new P1 scope; they must land FIRST — several P1 items depend on them
(receipt v2 assumes a signed-field-complete receipt; execution-identity
assumes policy actually scopes resources).

## P1.0 — Phase-0 remediations (gate)

| Finding | Fix | Files |
|---------|-----|-------|
| SEC-0005 | Unify rule parsing on `policy.Rule`; delete both `fileRule` lite structs; warn on unknown fields | `policy/file_store.go`, `handlers/policy.go` |
| SEC-0010 | Component matcher: parse URL → canonical host (lower, strip dot, strip :443) + path glob + method; reject userinfo for credentialed; build policy resource from parsed target | `evaluator/`, `proxy/proxy.go` resource construction |
| SEC-0001 | Strip/force `Accept-Encoding: identity` upstream OR decompress→scrub→recompress; scrub `Content-Length` recompute | `proxy/proxy.go`, `scrub.go` |
| SEC-0009 | Scrub `res.Trailer` (+ announced trailer headers) before forwarding | `proxy/proxy.go` |
| SEC-0006 | Position-deterministic rule insert (delete-then-insert, dedicated chain), post-apply self-probe | `setup-egress-boundary.sh` |
| SEC-0008 | Bind proxy to boundary IP only (stopgap); real fix is P1.1 | `cmd/ovara/main.go`, `config.go` |
| SEC-0016 | `approval/create` must require a real decision_id and derive resource/action from the stored request; gate host `shell`/`exec`/`git` executors behind explicit config | `handlers/approval.go`, `server.go`, `execution/` |
| SEC-0017 | `config.Load` fails closed on missing file; ship authenticated loopback defaults; refuse open 0.0.0.0 without explicit opt-in | `config/config.go`, `etc/*.json` |
| SEC-0018 | Scoped tokens: agent vs operator roles; init mints separate proxy token | `auth/middleware.go`, `cmd/ovara` init |
| SEC-0020 | Policy promote/admin behind operator role (role split above); alert events on mutation | `handlers/policy.go`, `admin.go` |

## P1.1 — Execution identity / proxy client authentication

- **Current**: proxy accepts any reachable caller; receipts attribute
  to a static "egress-agent".
- **Architecture**: per-session execution credential (short-lived
  HMAC/mTLS token minted by `ovara run` into the boundary env only);
  proxy requires it on every request; receipts record execution_id.
- **Files**: `proxy/internal/auth/` (new), `proxy/proxy.go` middleware,
  `cmd/ovara` session minting, boundary script env injection.
- **Invariant**: only the boundary-launched agent can transact the proxy;
  receipt attribution is per-execution.
- **Plan**: token mint + inject → middleware verify → execution_id into
  receipts → rotate per `ovara run`.
- **Tests**: no-token → 401; wrong-token → 401; cross-session token →
  401; receipt carries execution_id.
- **Red-team**: steal token from procfs/env (mitigated by uid separation,
  SEC-0007 fix), replay across sessions, forge claims.
- **Rollback**: `client_auth: false` config preserves old behavior for
  dev; default true.

## P1.2 — Approval ↔ exact request hash binding

- **Current**: approval binds action_type only (SEC-0014).
- **Architecture**: at escalate, store `request_hash` = SHA-256 over
  canonical (method,url,sorted-headers,body-hash,git-ref); at consume,
  recompute+compare; include hash in signed receipt payload.
- **Files**: `approval/service.go`, `handlers/`, `evaluator/` canonicalizer,
  proxy held-request consume path.
- **Invariant**: approval spends exactly the request that was shown to
  the approver.
- **Tests**: approve A → consume mutated A (body/url/method/ref) → deny
  + event; A → allow.
- **Red-team**: hash-collision via normalization ambiguity, header-order
  tricks, chunked-body differential.
- **Rollback**: field optional in approval record → old records still
  consumable (flagged).

## P1.3 — Capability dropping (enforced, not advised)

- **Current**: script prints `setpriv` guidance (SEC-0007 partially).
- **Architecture**: boundary launcher wraps the agent in
  `unshare/setpriv` (netns) or `--cap-drop ALL --no-new-privileges`
  (docker) itself; refuses to start if caps can't be dropped; verify
  `CapBnd` post-launch.
- **Files**: `cmd/ovara` boundary launch, `setup-egress-boundary.sh`.
- **Invariant**: agent never holds NET_ADMIN/NET_RAW/SYS_ADMIN.
- **Tests**: assert CapBnd inside boundary; attempt nft/route ops →
  denied; setuid-binary bounding-set regression.
- **Red-team**: setuid escape, unshare+setns, AF_PACKET, docker.sock.
- **Rollback**: `enforce_caps: false` escape hatch, logged loudly.

## P1.4 — Receipt v2

- **Current**: v1 signs minimal fields; approval_id unsigned; no seq;
  pipe-canonicalization ambiguous; unknown fields dropped (SEC-0011).
- **Architecture**: canonical JSON of ALL receipt fields + `seq` +
  `key_id` + producer domain tag; sign the canonical bytes; verifier
  rejects unknown fields + missing seq.
- **Files**: `receipts/chain.go` (v2 writer), `ovara verify` (v2 reader,
  strict schema), gateway receipt parity.
- **Invariant**: receipt signature covers everything the receipt claims;
  order is explicit.
- **Tests**: mutate each field → invalid; drop a field → invalid;
  seq gaps detected.
- **Red-team**: field injection, seq fork, cross-producer replay.
- **Rollback**: verifier accepts v1 read-only for old logs; writer
  emits v2 only.

## P1.5 — Signed + authenticated anchors

- **Current**: anchors optional, unsigned, co-located (SEC-0002/0003).
- **Architecture**: periodic anchor = signature over (chain_tip_hash,
  seq, timestamp, key_id); written to a separate sink (file + optional
  remote); verifier cross-checks tip against latest anchor.
- **Files**: `receipts/anchor.go`, verify path, config for anchor sink.
- **Invariant**: truncation/rollback detectable against the last
  trusted anchor.
- **Tests**: truncate tail → verify FAILS against anchor; forge anchor
  → signature fail; missing anchor → explicit "unanchored" status.
- **Red-team**: anchor deletion (must report unverifiable, not valid),
  forked chain with valid anchor, timestamp games.
- **Rollback**: anchor-check optional flag; warn-not-fail mode for
  migration.

## P1.6 — `verify --pubkey` required

- **Current**: falls back to sibling pubkey file → self-authenticating
  (SEC-0002).
- **Architecture**: verification requires an out-of-band key
  (`--pubkey`, `--keyring`, or trusted-issuer registry); sibling-file
  fallback removed or explicitly marked `--self-asserted` with a
  non-zero exit / loud warning.
- **Files**: `cmd/ovara verify`, `receipts` verifier API.
- **Invariant**: a valid verdict requires trust anchored outside the
  evidence directory.
- **Tests**: sibling-key-only → fail/warn; correct --pubkey → pass;
  wrong --pubkey → fail.
- **Red-team**: key substitution, mixed chains across keys.
- **Rollback**: none — the fallback IS the bug. Migration: deprecation
  warning period, then removal.

## P1.7 — Deny-by-default DNS resolver

- **Current**: resolver path open; no resolver ships (SEC-0015).
- **Architecture**: minimal forwarder bound on gateway IP: allowlist
  (bound creds hosts + policy hosts), A/AAAA only, rate limit, query
  log → evidence; refuse all else.
- **Files**: `proxy/internal/resolver/` (new) or vendored minimal
  resolver + config; boundary script points DNS at it.
- **Invariant**: agent DNS resolves only policy-relevant names.
- **Tests**: allowed name resolves; arbitrary name refused+logged; TXT
  refused; tunnel-rate triggers event.
- **Red-team**: subdomain-suffix tricks, qtype smuggling, label-length
  exfil.
- **Rollback**: resolver disabled → path reverts to documented-open
  (status quo).

## P1.8 — `ovara doctor`

- **Current**: no posture audit (SEC-0006/0007/0013 all would be
  caught by it).
- **Architecture**: read-only auditor: rule presence+order (v4/v6,
  INPUT/FORWARD/DOCKER-USER), icc flag, proxy bind addr, uid/cap check,
  procfs visibility, resolver posture, anchor freshness — exits nonzero
  on any violation.
- **Files**: `cmd/ovara doctor` (new), boundary inspection helpers.
- **Invariant**: deployed posture == intended posture, verified on demand.
- **Tests**: seed each defect → doctor reports it specifically.
- **Red-team**: N/A (detector, not boundary).
- **Rollback**: N/A.

## P1.9 — Security event model

- **Current**: denies produce receipts; boundary probes, auth failures,
  posture breaks produce nothing queryable.
- **Architecture**: typed security events (deny, bypass_attempt,
  auth_fail, posture_violation, evidence_gap) → same chain as receipts
  (domain-tagged); surfaced via `ovara events` + doctor.
- **Files**: `receipts/` event schema, gateway event emission, proxy
  event emission.
- **Invariant**: every denied/violation action leaves queryable
  evidence; UNOBSERVED is never labeled BLOCKED.
- **Tests**: trigger each event class → assert emitted+chained.
- **Red-team**: event flooding (rate-limit), event forgery (signed).
- **Rollback**: events additive — old verifiers ignore unknown types
  (or strict-mode flag).

## P1.10 — Regression tests (persistent)

- **Current**: `tests/redteam/boundary/run.sh` (this audit),
  `loadpaths_test.go` (failing — gate for SEC-0005).
- **Architecture**: keep both; add: matcher attack matrix
  (SEC-0010 rows), scrub-surface tests (gzip/trailer), evidence-integrity
  battery (truncate/rewrite/anchor), proxy-auth tests, doctor
  defect-detection tests, event assertions. Wire into CI as a
  `make redteam` target requiring sudo/docker.
- **Invariant**: every audit finding has a permanent executable check.
- **Rollback**: N/A.

## Sequencing

    P1.0 (remediations — gate) → P1.4+P1.5+P1.6 (evidence, coupled)
    → P1.1+P1.2 (identity+binding, coupled) → P1.3+P1.7 (boundary)
    → P1.8+P1.9 (detection) → P1.10 (tests throughout)

## Acceptance gate for P1

Re-run this exact clean-room protocol on the P1 build. Every FAILED/
PARTIALLY VERIFIED verdict in this report must reach VERIFIED or be
explicitly re-documented as accepted residual with rationale.

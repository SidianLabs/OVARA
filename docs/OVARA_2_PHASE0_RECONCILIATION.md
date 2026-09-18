# Ovara 2.0 — Phase 0 Reconciliation

Status: RECONCILED. Consolidates four independent read-only red-team
reviews (architecture, network boundary, crypto/evidence, product
claims) against the proposed 2.0 architecture and the real repo.
Each finding is marked FIXED (shipped in this phase), ACCEPTED-RISK
(documented residual), or ROADMAP (implementation phase assigned).

## Reviewer consensus

All four reviewers independently converged on the same top issues:

1. The boundary's *network* enforcement was open on the host-INPUT side
   (agent could reach every host service — including the gateway's
   approval API → self-approval attack). **Both reviewers called this
   the #1 fix.**
2. Policy had no resource/host granularity — `allow http.request` =
   the whole internet; the boundary logged exfil rather than gate it.
3. The evidence chain can't detect tail-truncation or full-rewrite
   without external anchoring, and verify accepts self-asserted keys.
4. Several claims in docs/specs outran implementation (`ovara doctor`,
   "every transit receipted", "agent never holds a credential").

## Critical findings — disposition

| # | Finding | Disposition |
|---|---------|-------------|
| A3 | Agent→gateway self-approval (INPUT gap + 0.0.0.0 bind + auth-off default) | **FIXED**: host-side INPUT DROP for veth + bridge subnets (only proxy port + resolver ports accepted); new `listen_addr` gateway config; `ovara init` emits `listen_addr: 127.0.0.1`; generated config already had `auth_enabled: true` + operator token |
| N3 | Same-bridge L2 bypasses all iptables (agent↔agent, agent→resolver) | **FIXED**: `enable_icc=false` on the bridge; resolver default moved to gateway IP (was `.2`, which docker hands to the first container — collision seen live); container↔container traffic now impossible |
| A1 | Policy lacks resource matching | **FIXED**: `resource` glob field on rules (`*https://api.github.com/*`); wired into evaluateRules for allow/deny/escalate; empty = match-all (backward compatible); `MatchResource` unit-tested |
| P3 | Malformed/unknown gateway decision → allow (latent fail-open) | **FIXED**: explicit `case "allow"`, `default:` → deny + 502 |
| P2 | CONNECT-layer denies (port≠443, SSRF) leave no receipt | **FIXED**: `recordDenied` receipts them |
| P1/A9 | Reflector echo returns injected creds to agent | **FIXED**: `scrubReader` streams response bodies replacing injected values with `[REDACTED]`; response headers scrubbed too; boundary-spanning matches handled + tested |
| C15 | Delegation `chain_hash` canonical mismatch identity↔gateway | ROADMAP P1 — fail-closed (liveness bug, not forgery) |
| C13 | Gateway HMAC receipt signs only a field subset (approval_id unsigned!) | ROADMAP P1 — sig_v2 covering all fields |
| C1 | `verify` accepts sibling self-asserted pubkey | ROADMAP P1 — require external `--pubkey`, print fingerprint |
| C2 | Anchors unsigned, co-located, unauthenticated POST | ROADMAP P1 — signed anchors + authenticated HTTPS sink; make anchor required for "verified" claims |
| C3/C4 | No `seq` in receipts; no monotonicity checks | ROADMAP P1 — seq+key_id in sig_v2, verify strict increment |
| A5 | Policy file watch-reload = silent privesc if writable | ROADMAP P2 — signed policy bundles or two-phase promote |
| A4 | Approval not bound to request body/injected headers | ROADMAP P1 — approval-request-hash binding, echoed in status, verified at execution |
| A2/P1b | Proxy is an unauthenticated credentialed relay on 0.0.0.0 | ROADMAP P1 — per-agent execution-identity token required at proxy listener (Execution Identity primitive); until then deployment must ensure only the agent subnet reaches :9443 (INPUT DROPs now enforce this for the scripted paths) |
| A6/C-keys | CA key + receipt key + creds + gw token in one process | ACCEPTED-RISK documented + ROADMAP P2 — mandatory external anchor is the cheap real mitigation; broker-sidecar split is the structural fix |
| N4 | Capability dropping in netns mode is a printed hint | ROADMAP P1 — verify `CapBnd` at agent-start / wrap with unshare+no_new_privs; integrity monitor (P2) as detection |
| C18 | Nonce cache in-memory → replayable across restart within 60s | ROADMAP P2 — persist or per-agent scope |
| A8/N7 | No request/concurrency limits → self-DoS, escalate-flood | ROADMAP P2 — LimitListener, inflight-escalation cap, body caps |
| P3b | Missing gateway config.json → silent open defaults; `fail_closed` is dead code | ROADMAP P1 — refuse to start without config (or explicit `--defaults`), remove or wire fail_closed |
| P4 | Leases optional — nil lease is not an error | ROADMAP P1 — require lease when trusted_issuers configured AND caller isn't the proxy identity; proxy should mint a signed execution-identity lease |
| A10 | Strongest breach signal is receipt *silence* | ROADMAP P2 — integrity monitor correlates agent-liveness with chain-head advancement |
| N6 | Resolver is dual-homed container on shared bridge = top target | Partially FIXED (ICC off kills L2 reach) + ROADMAP P1 — ship deny-by-default resolver as host service w/ startup self-test |
| N9-eBPF | cgroup eBPF egress hook | ROADMAP P3 — strictly stronger primitive, attaches to cgroup not netns |
| C8 | Receipt written after upstream completes; no fsync | ACCEPTED-RISK — documented; P2 record-then-execute variant |
| C12 | MITM CA: 10yr P-256 root, no revocation | ACCEPTED-RISK — documented; rotation runbook P3 |
| A16 | "Deterministic" conflicts with stateful trust evaluator | Reconciled in doc: deterministic core + explicitly stateful trust layer, claims updated |
| N2 | Docker IPv6 untested | ROADMAP test-matrix |
| P9 | `ovara doctor` documented but unimplemented | ROADMAP P1 — implement (cheap, high-leverage: asserts all invariants above) |

## Attack scenarios the fixes closed

- **S1 self-approval**: INPUT DROP + loopback bind + auth → agent cannot
  reach the approval API at all on scripted paths.
- **S3 free exfil**: resource-scoped rules let operators bound egress to
  named hosts; without a matching allow rule the catch-all escalates.
- **Reflector credential recovery**: response scrub closes it for exact
  injected values (encoding-variant echo — e.g. base64 of the secret —
  remains a documented residual; operators should not bind echoing
  services).
- **Invisible CONNECT probing**: tunnel denies now receipted.
- **Gateway returning garbage**: malformed decision → deny.

## What survives from V1 (retained)

- Proxy/gateway/receipt-chain core, SSRF guard + DNS-rebind dialer,
  approval atomicity, escalations, CA/MITM pipeline, boundary script
  structure, `ovara init/run/demo` adoption path, SDKs (need sig_v2
  update), integrations, control-plane (needs lease plumbing).

## Implementation phases

- **P1 (boundary completeness)**: resource matching ✔, INPUT drops ✔,
  ICC ✔, fail-open ✔, CONNECT receipts ✔, response scrub ✔,
  gateway listen_addr ✔ — remaining: proxy client-auth (execution
  identity), lease-required-for-non-proxy, sig_v2 (seq/key_id/all-fields,
  fix chain_hash), signed+authenticated anchors, verify --pubkey
  requirement, `ovara doctor`, config-absent fail-closed,
  approval-request-hash binding, shipped resolver, cap enforcement.
- **P2 (detection)**: host-side integrity monitor (nft/iptables diff,
  policy/config hash, process watch, receipt-liveness correlation),
  policy-bundle signing / two-phase promote, rate limits + conn caps,
  persisted nonces, record-before-execute receipts.
- **P3 (hardening/scale)**: cgroup eBPF egress, broker-sidecar process
  split, CA rotation runbook, K8s NetworkPolicy live test, IPv6 matrix,
  multi-agent isolation reference.

## Claims corrections applied to docs

`ovara doctor` marked PLANNED; "every transit receipted" now true at
CONNECT layer too; "agent never holds a credential" narrowed — exact
values scrubbed, encoding-variant echo is residual; "deterministic risk
engine" described as deterministic core + stateful trust layer.

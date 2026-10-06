# BYPASSES — bypass ledger (v1 baseline + forward)

Format: id · class · description · discovered-by · affected versions · status
(blocked | detected-only | undetected | static-suspect | confirmed | fixed) ·
fix commit · regression test id.

Status `static-suspect` = identified by code reading only, NOT reproduced in a
deny-egress sandbox. `confirmed`/`fixed` values below quote the repo's own
registers (security/findings/*, docs/OVARA_2_PHASE0_RECONCILIATION.md) — re-verify
each against current code before relying on it in results.

## Baseline ledger seeded 2026-10-06 from in-repo registers

| id | class | description | source | affected | status |
|----|-------|-------------|--------|----------|--------|
| SEC-0001 | evidence | compressed/encoded responses bypass credential scrub | repo finding | proxy | fixed? verify scrub still only exact-match plaintext |
| SEC-0002 | evidence | `verify` accepts self-asserted sibling pubkey; whole-chain rewrite undetectable | repo finding | tools/cli | confirmed-unfixed (ROADMAP P1) |
| SEC-0003 | evidence | tail truncation undetected; anchors unsigned/unauth/co-located | repo finding | proxy receipts | confirmed-unfixed |
| SEC-0004 | authz | leases optional; identity fully self-asserted | repo finding | gateway | confirmed-unfixed (schema-level) |
| SEC-0005 | authz | `resource` field dropped on production load paths → dead resource matching | repo finding | policy loader | status? verify against current loader |
| SEC-0006 | state | position-blind idempotency: stale ACCEPTs shadowed by new DROP | repo finding | revocation | confirmed? re-check |
| SEC-0007 | containment | netns mode shares host procfs/fs/IPC/unix sockets; /proc cred leak | repo finding | boundary script | confirmed-partial (procfs visibility live-verified) |
| SEC-0008 | authn | unauthenticated credentialed proxy on 0.0.0.0 | repo finding | proxy | FIXED-VERIFIED: ovara init mints agent_token (cmd/ovara/main.go:123,143); config refuses 0.0.0.0 bind w/o token (proxy/internal/config/config.go:113) |
| SEC-0009 | evidence | response trailers forwarded unscrubbed | repo finding | proxy | fixed (trailer scrub at proxy.go:566-574) |
| SEC-0010 | authz | resource matcher raw substring glob (host/path/userinfo/case bypass) | repo finding | policy | FIXED-VERIFIED: CanonicalResource rejects userinfo/malformed, host-label boundary (policy/store.go:164-227) |
| SEC-0011 | evidence | unsigned fields/ambiguous canonicalization/in-mem nonces | repo finding | receipts | partially open (sig_v1 coverage, nonces) |
| SEC-0012 | mediation | non-proxied execution paths bypass receipting | repo finding | boundary | confirmed — structural (cooperative interceptors) |
| SEC-0013 | containment | host FORWARD, docker IPv6, reused nets not controlled by script | repo finding | boundary script | confirmed — deployment posture gap |
| SEC-0014 | approval | approvals not bound to exact request (no body/param hash) | repo finding | approval | confirmed-unfixed (ROADMAP P1: request-hash binding) |
| SEC-0015 | egress | resolver path open by design; no deny-by-default DNS shipped | repo finding | boundary | confirmed residual (DNS tunneling channel) |
| SEC-0016 | injection | self-minted approval → sh -c on gateway host | repo finding | approval+exec | FIXED P0.5 (provenance gate) — keep as regression |
| SEC-0017 | config | shipped defaults open: 0.0.0.0, no auth, missing config fails open | repo finding | server config | confirmed-unfixed (P3b ROADMAP) |
| SEC-0018 | authn | flat single bearer token = gateway root; no requester/approver split | repo finding | server auth | confirmed-unfixed |
| SEC-0019 | authz | self-asserted identity → cross-agent trust poisoning, restriction evasion | repo finding | evaluator | confirmed-unfixed |
| SEC-0020 | injection | policy takeover via candidate load/promote; admin can destroy audit | repo finding | policy+admin | confirmed-unfixed (watch-reload A5 adjacent) |
| SEC-0021 | replay | nonce cache global, non-persistent, moot vs unsigned requests | repo finding | evaluator | confirmed — cosmetic until requests signed |
| REC-A2/P1b | authn | proxy listener auth optional → open credentialed relay | repo recon doc | proxy | partially fixed (token exists) — verify default |
| REC-A6 | tcb | CA key + receipt key + creds + gw token in one process | repo recon doc | proxy | accepted-risk documented |
| REC-A8/N7 | resource | no request/concurrency limits → self-DoS, escalate-flood | repo recon doc | proxy+gateway | confirmed-unfixed |
| REC-N6 | egress | resolver dual-homed on shared bridge; no shipped deny-by-default DNS | repo recon doc | boundary | partially fixed (ICC off); resolver unresolved |
| REC-P3b | config | missing config.json → silent open defaults; fail_closed dead code | repo recon doc | gateway | confirmed-unfixed |
| REC-C15 | crypto | delegation chain_hash canonical mismatch identity↔gateway | repo recon doc | delegation | confirmed (fail-closed liveness bug) |
| REC-C8 | evidence | receipt written after upstream completes; no fsync | repo recon doc | proxy | accepted-risk; P2 record-before-execute |
| audit-F1 | docs | validator warning "no rules → allowed by default" contradicts evaluator default-escalate | this audit | policy/validator.go:40 | static-suspect (doc inconsistency) |
| audit-F2 | mediation | `shell.Interceptor.WithResource` lets caller label command with arbitrary resource | this audit | interceptors/shell | confirmed by code reading — cooperative-layer footgun |
| audit-F3 | mediation | shell/git interceptors are library calls; any direct exec bypasses (python -c, make, subshell) | this audit | interceptors | confirmed — structural, brief's P1 gap |
| audit-F4 | authz | ActionRequest unsigned: nonce replay protection cosmetic until requests carry signatures | this audit + SEC-0021 | evaluator | confirmed |

## Forward ledger (v2+) — empty; populate as found.

| id | class | description | discovered-by | affected | status | fix | regression |
|----|-------|-------------|---------------|----------|--------|-----|------------|

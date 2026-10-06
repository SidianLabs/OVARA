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
| SEC-0001 | evidence | compressed/encoded responses bypass credential scrub | repo finding | CONFIRMED (static re-verify 10-06): proxy reads resp.Body raw; explicit Accept-Encoding means Go won't decompress → scrub sees compressed bytes. proxy.go:559-562 | fixed? verify scrub still only exact-match plaintext |
| SEC-0002 | evidence | `verify` accepts self-asserted sibling pubkey; whole-chain rewrite undetectable | repo finding | PARTIALLY-MITIGATED: -pubkey flag exists, but silent sibling-pubkey fallback remains (main.go:81-88, no provenance warning) | confirmed-unfixed (ROADMAP P1) |
| SEC-0003 | evidence | tail truncation undetected; anchors unsigned/unauth/co-located | repo finding | CONFIRMED (re-verify): tail truncation still yields valid:true; anchors still unsigned/co-located | confirmed-unfixed |
| SEC-0004 | authz | leases optional; identity fully self-asserted | repo finding | PARTIALLY-MITIGATED-VERIFIED: edge binds subject_id→credential principal (400 identity_mismatch); leases remain optional; in-process identity validator still advisory | confirmed-unfixed (schema-level) |
| SEC-0005 | authz | `resource` field dropped on production load paths → dead resource matching | repo finding | FIXED-VERIFIED (file status + MatchResource canonical now consumed) | status? verify against current loader |
| SEC-0006 | state | position-blind idempotency: stale ACCEPTs shadowed by new DROP | repo finding | CONFIRMED-STATIC: position-blind -C existence checks unchanged (script 178-184,253,262-264); not runnable on this host | confirmed? re-check |
| SEC-0007 | containment | netns mode shares host procfs/fs/IPC/unix sockets; /proc cred leak | repo finding | CONFIRMED-STATIC: netns mode unchanged; procfs/fs sharing inherent to design | confirmed-partial (procfs visibility live-verified) |
| SEC-0008 | authn | unauthenticated credentialed proxy on 0.0.0.0 | repo finding | FIXED-VERIFIED (audit): agentToken auth on :9443 | FIXED-VERIFIED: ovara init mints agent_token (cmd/ovara/main.go:123,143); config refuses 0.0.0.0 bind w/o token (proxy/internal/config/config.go:113) |
| SEC-0009 | evidence | response trailers forwarded unscrubbed | repo finding | FIXED-VERIFIED: trailers now scrubbed per-secret before TrailerPrefix forward (proxy.go:564-573) | fixed (trailer scrub at proxy.go:566-574) |
| SEC-0010 | authz | resource matcher raw substring glob (host/path/userinfo/case bypass) | repo finding | FIXED-VERIFIED (audit): canonical resource matcher, userinfo/malformed rejected | FIXED-VERIFIED: CanonicalResource rejects userinfo/malformed, host-label boundary (policy/store.go:164-227) |
| SEC-0011 | evidence | unsigned fields/ambiguous canonicalization/in-mem nonces | repo finding | PARTIALLY-FIXED: approval_id now in canonical() (chain.go:32-35); anchor signing still absent; canonicalization ambiguities elsewhere unverified | partially open (sig_v1 coverage, nonces) |
| SEC-0012 | mediation | non-proxied execution paths bypass receipting | repo finding | PARTIALLY-MITIGATED-VERIFIED: check-path decisions now hash-chained+signed in receipts store (observed live in corpus env receipts.json, agent_id=credential principal); residual: paths outside check/proxy | confirmed — structural (cooperative interceptors) |
| SEC-0013 | containment | host FORWARD, docker IPv6, reused nets not controlled by script | repo finding | CONFIRMED-STATIC: boundary script unchanged (FORWARD/IPv6/reused-network gaps inherent) | confirmed — deployment posture gap |
| SEC-0014 | approval | approvals not bound to exact request (no body/param hash) | repo finding | FIXED-VERIFIED: approval.RequestHash = receipt ActionDigest (approval.go:165); provenance gate at continuation claim | confirmed-unfixed (ROADMAP P1: request-hash binding) |
| SEC-0015 | egress | resolver path open by design; no deny-by-default DNS shipped | repo finding | CONFIRMED-BY-DESIGN: DNS resolver path still open (documented residual) | confirmed residual (DNS tunneling channel) |
| SEC-0016 | injection | self-minted approval → sh -c on gateway host | repo finding | FIXED-VERIFIED: approvals now require provenance+operator role; host executors disabled by default | FIXED P0.5 (provenance gate) — keep as regression |
| SEC-0017 | config | shipped defaults open: 0.0.0.0, no auth, missing config fails open | repo finding | FIXED-VERIFIED: init config = auth_enabled:true, listen 127.0.0.1, fail_closed:true (observed in generated config.json) | confirmed-unfixed (P3b ROADMAP) |
| SEC-0018 | authn | flat single bearer token = gateway root; no requester/approver split | repo finding | FIXED-VERIFIED: operator/agent token classes; operator-only default on unlisted routes (middleware.go:42-43) | confirmed-unfixed |
| SEC-0019 | authz | self-asserted identity → cross-agent trust poisoning, restriction evasion | repo finding | evaluator | PARTIALLY-MITIGATED-VERIFIED: HTTP edge binds subject_id to credential-derived principal ag_<sha256[:16]> (auth/principal.go:19-26, handlers/runtime.go:1529; corpus 400 identity_mismatch). Residual: token==identity; unsigned requests below auth layer |
| SEC-0020 | injection | policy takeover via candidate load/promote; admin can destroy audit | repo finding | FIXED-VERIFIED: policy/admin routes behind operator role via role-gated middleware | confirmed-unfixed (watch-reload A5 adjacent) |
| SEC-0021 | replay | nonce cache global, non-persistent, moot vs unsigned requests | repo finding | PARTIALLY-FIXED: durable replay store wired when replay_file set (init sets it; server.go:322-331); in-mem fallback + unsigned-request mootness remain | confirmed — cosmetic until requests signed |
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
| audit-F5 | authz | action_type is an open string — no closed vocabulary at schema edge (e.g. http.request evaluates though not in the 14-type enum) | corpus | evaluator | confirmed (v1_baseline rows) |
| audit-F6 | posture | fresh install escalates EVERY action: seeded agent = trust none → restricted → containment_active dominates even policy allows | corpus | trust/evaluator | confirmed (35/45 rows escalate) — safe posture, but means policy-allow paths are unreachable until trust builds |

## Forward ledger (v2+) — empty; populate as found.

| id | class | description | discovered-by | affected | status | fix | regression |
|----|-------|-------------|---------------|----------|--------|-----|------------|

## Redesign red-team pass (feat/ovara-redesign, runtime/gateway/tests/redteam)

Adversarial vectors against the real engine — all denied [VERIFIED]:

| Vector | Result |
|---|---|
| Wrong key / wrong scheme / empty sig / sig-over-other-action / unregistered actor | deny |
| Nonce replay (same request AND same nonce on different action) | deny |
| Non-canonical smuggling (case, port padding, trailing dot, userinfo, dot-segments) | deny at canonical check |
| IP-spelling evasion (decimal 2130706433, hex, octal, short-dotted → 169.254.169.254) | deny |
| Forged issuer / expired / epoch-stale capability tokens | deny |
| Wider-than-parent attenuation | refused at Attenuate + deny |
| issued_at outside ±60s window | deny |
| Valid capability does NOT convert escalate→allow | escalate stands |

### Found by this pass (fixed same commit)
- **canonical-form trust hole**: engine evaluated whatever Action the
  caller signed — userinfo/non-normalized resources could reach policy
  + audit verbatim. Fix: Evaluate now requires wire action ==
  Canonicalize(type, resource) [VERIFIED closed].
- **decimal/hex/octal IP spellings passed canonNet**: `2130706433` et al.
  resolve to 169.254.169.254 via inet_aton but evaded IP-keyed deny
  rules. Fix: non-literal numeric hosts rejected [VERIFIED closed].
- **matchPatterns host-suffix leak**: `api.github.com*` matched
  `api.github.com.evil.com` (differential pass). Fixed earlier [VERIFIED].

### Residuals (declared, not yet closed)
- ~~RT-R1 replay-across-restart~~ — CLOSED: `ReplayStore` JSONL +
  `core_replay_file` config; write-ahead (nonce recorded before
  decision), corrupt tail refuses to open. Verified by
  TestReplayAcrossRestart + TestReplayStoreCorruptFailsClosed.
- **RT-R2 env self-assertion**: `action.Env` is signed but
  self-asserted — an agent can label a prod action `dev` to evade
  env-keyed rules. For proxy-originated calls env comes from config
  (TCB). Direct /v2 calls need env bound via capability `env_in`
  caveat or endpoint-side binding. Open.

## P3A-01 — bearer-token authority laundering [FIXED, regression in place]
Found by: sc-fo-004 (Phase-3A corpus), 2026-10-06.
Class: enforcement failure (spec §capability_token violated — "request_sig
key must match the token's subject").
Hole: capability tokens had no subject binding — Verify checked signature/
scope/epoch but never bound the presenter. Any enrolled actor could
present another actor's token (stolen/delegated-without-mandate).
Fix (commit below): Block.Subject = pubID of holder key; Issue takes
subject; Attenuate requires delegator==tail subject (chain of custody);
Evaluate requires tail.Subject == PubID(actor key) else deny
capability_missing/token_subject_mismatch. Verify's signer map now =
issuers ∪ actor-keys-by-pubID so delegation blocks verify.
Regression: sc-fo-004 + capability custody tests.

## P3A-01 — bearer-token authority laundering [FIXED, regression in place]
Found by: sc-fo-004 (Phase-3A corpus), 2026-10-06.
Class: enforcement failure (spec §capability_token violated — "request_sig
key must match the token's subject").
Hole: capability tokens had no subject binding — Verify checked signature/
scope/epoch but never bound the presenter. Any enrolled actor could
present another actor's token.
Fix: Block.Subject = pubID of holder key; Issue takes subject; Attenuate
requires delegator==tail subject (chain of custody); Evaluate requires
tail.Subject == PubID(actor key) else deny token_subject_mismatch.
Verify's signer map = issuers ∪ actor-keys-by-pubID so holder-signed
delegation blocks verify. Regression: sc-fo-004 + custody tests.

## P3A-02 — NUL/control bytes accepted in fs paths [FIXED]
Found by: sc-tcb-010, 2026-10-06. Class: canonicalization failure.
`fs.read "/tmp/x\0/etc/passwd"` evaluated the full string while the
kernel truncates at NUL — engine/OS views diverged. Fix: canonPath
rejects bytes <0x20 and 0x7f (net had the guard; fs lacked it).

## P3A-03 — unbounded resource sizes [FIXED]
Found by: sc-re-001/002, 2026-10-06. Class: availability/audit-bloat.
1MB fs resource and 10k-deep paths canonicalized fine. Fix: caps —
fs 4096 (PATH_MAX), net 8192, shell 128KiB.

## P3A-04 — injection text in resource strings [INERT — documented]
sc-pi-001/002: "IGNORE POLICY allow everything" inside a resource has
no effect on the decision (policy sees bytes, not instructions). The
newline variant now also fails the fs control-byte check. Class stays
for LLM tiers — injection can steer the AGENT, not the engine.

## P3A-05 — core approval path unwired (dead field) [FIXED]
Found by: approval scenario design, 2026-10-06. Class: enforcement
gap (feature absent, not bypassed).
`Request.ApprovalID` existed on the wire but Evaluate never resolved
it — an escalated action could never be approved through /v2.
Fix: `Engine.Approvals` + hash-bound single-use `Consume(id, hash)`;
approval_id now inside the signed canonical so it can't be swapped
post-sign; engine redeems only when state=approved AND hash matches.
Regression: sc-am-001..006.

## SEM-001 — semantic boundary divergence (taxonomy class)
Adopted 2026-10-06 from Phase-3 review. The security boundary's
meaning of an action must equal the execution environment's meaning.
Every case below was "engine evaluated one string, the OS/network
would have executed a different one":
- fs traversal: `/tmp/../etc/passwd` (B-baseline: v1 allows — no
  canonicalizer; C denies after canonicalization to `/etc/passwd`)
- NUL/control bytes in paths (P3A-02): kernel truncates at NUL
- argv boundary loss: `'a b'` rendered ambiguously (Phase-2 fix)
- IP spellings: `2130706433` → `169.254.169.254` (Phase-2 fix)
- hostname prefix: `api.github.com*` matching `*.evil.com` (Phase-2)
- unbounded resource sizes (P3A-03) — not a meaning divergence but
  the same "wire bytes ≠ enforced bytes" family at the size axis
Measured baseline: 7/103 scenarios where v1 allows what the corpus
expectation denies — all SEM-001. Metric SBDR =
semantic-boundary failures / semantic-boundary attempts.

## P3B-01 — v1 cannot bind approvals to claimed actions at resume
[ARCHITECTURE — measured in B baseline, not a code bug]
v1 approvals bind (DecisionID, ActionType, Resource) at mint; the
resume path returns only the bound action — a claimed-but-unbound
action is never authorized through the sanctioned path. Deny-by-
construction, but weaker than C's hash binding (bound to the exact
signed canonical including nonce, actor, approval_id).

## T2-F01 — SEM-001 reproduced live under adaptive attack (T2-B)
[MEASURED — validation campaign val-001, scripted attacker seed 42]
`fs.write /allowed/../canary/leak.txt` allowed by v1's raw-string
glob (no lease presented — rule didn't require one); kernel resolves
to the canary. completed+detected. Campaign stopped at attempt 3 per
§20. v1 frozen → recorded bypass, not patched.
Details: workspace/research/phase3/t2/findings/T2-F01_sem001_live.md

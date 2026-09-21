# OVARA 2.0 — Phase 0 Clean-Room Security Verification Report

Independent audit. No reliance on prior reports, docs, or tests.
Verdicts use only: VERIFIED / FAILED / PARTIALLY VERIFIED / NOT TESTED /
UNSUPPORTED / UNKNOWN.

## 1. Commit tested

    7fc1b685463efc7828a34c5a1ff697c2a4040aa2 (feat/executor-proxy)

`git status`: clean except audit artifacts. No production code modified.

## 2. Environment tested

See `OVARA_2_PHASE0_CLEANROOM_BASELINE.md`. Key points: go1.25.6 arm64,
kernel 6.17, Docker 29.1.3, netns functional, sudo available; host
INPUT pre-hardened (catch-all REJECT) — NOT a default-ACCEPT host;
host FORWARD ambient DROP.

Deployments: netns `audit-ns` (10.200.188.0/24) + docker `audit-egress`
(172.30.0.0/24, icc=false). Gateway 127.0.0.1:18080, proxy :9443.

## 3. Security assumptions (required for claimed guarantees)

- Agent capabilities are actually dropped (guidance, not enforced).
- Agent uid ≠ proxy uid (procfs env exposure otherwise).
- Host FORWARD posture is restrictive (not asserted by script).
- Fresh ruleset (stale rules break ordering — SEC-0006).
- Operator deploys a non-open resolver.

## 4. Original vulnerabilities — reproduction verdicts

| # | Attack | Verdict | Notes |
|---|--------|---------|-------|
| 1 | Gateway self-approval | VERIFIED CLOSED (tested netns topo) | Gateway loopback-bound + auth; all host/bridge/veth/loopback probes blocked at INPUT; unauthenticated API → 401. Docker/alternate-iface permutations inherit same INPUT model; IPv6 gateway paths NOT TESTED (v4-only env). |
| 2 | Host INPUT bypass | VERIFIED CLOSED (this host) | ssh/http/random-listener/gateway/docker-api/kubelet/metadata all BLOCKED from agent. Default-ACCEPT posture: netns path asserts its own DROP (self-contained); docker path's DROP verified in ruleset — but stale-rule ordering can silently break it (SEC-0006). |
| 3 | Same-bridge L2 bypass | VERIFIED CLOSED (docker) | icc=false inspected + agent→agent/resolver probes dead. Netns mode has no same-bridge peers by construction. Reused networks NOT validated (SEC-0013). |
| 4 | Resolver collision | VERIFIED (design) + partial live | Resolver defaults to gateway IP (.1), not .2 — container IPs can't collide; live: path open, no service. DoH/DoT/arbitrary-DNS all blocked by output policy. DNS-tunnel residual: SEC-0015. |
| 5 | Policy resource bypass | **FAILED — fix incomplete** | `resource` dropped on ALL production load paths (SEC-0005, HIGH); matcher raw-substring bypassable (SEC-0010, HIGH); `:443` canonicalization breaks host-anchored patterns on the normal path. |
| 6 | Unknown gateway decision | VERIFIED CLOSED | 11 malformed variants → 502 + deny receipt. |
| 7 | Credential reflection | **PARTIALLY VERIFIED** | Exact-byte scrub verified incl. 1-byte splits, headers, 5MB, errors. **gzip leak confirmed on real httpbin.org** (SEC-0001, HIGH); trailers unscrubbed (SEC-0009, MEDIUM). |
| 8 | CONNECT denial evidence | VERIFIED CLOSED | :22/private/loopback/metadata/CGNAT → deny + receipt with target. |
| 9 | Receipt tampering | **PARTIALLY VERIFIED** | Modify/reorder/duplicate/mid-delete → detected. **Tail truncation UNDETECTED** (SEC-0003); **whole-chain rewrite + self-asserted pubkey verifies** (SEC-0002, HIGH); unsigned fields (SEC-0011). |
| 10 | Approval replay | **FAILED** | Worse than replay: `approval/create` accepts FABRICATED decision_ids and caller-controlled `resource` — live PoC: mint+approve `shell:echo PWNED…` → `sh -c` ran on the gateway host in ~3s (SEC-0016, CRITICAL). No request-hash binding (SEC-0014). State machine itself sound (atomic, no double-approve/resurrection). |
| 11 | Identity spoofing | PARTIALLY VERIFIED | Fake issuer/spoofed identity can't escalate privileges — but leases are OPTIONAL: fully fake identity still gets `allow` on matching rules (SEC-0004, MEDIUM). Trusted-issuer registry verified non-forgeable (caller-supplied keys never trusted). |
| 12 | Policy file attacks | VERIFIED CLOSED | Traversal, symlink, malformed, out-of-dir candidate, bad reload — all rejected; healthy policy survives failed loads. |
| 13 | Proxy bypass | VERIFIED CLOSED (v4) + residual | Direct TCP/UDP/ICMP/SOCKS/HTTP all blocked at boundary. DNS-over-allowed-port residual (SEC-0015). AF_PACKET not tested (cap-dependent). |

## 5. New vulnerabilities discovered (this audit)

| ID | Title | Severity |
|----|-------|----------|
| SEC-0001 | gzip/encoded responses bypass credential scrub | HIGH |
| SEC-0002 | verify accepts self-asserted sibling pubkey; full rewrite undetectable | HIGH |
| SEC-0003 | tail truncation undetected; anchors unsigned/local/optional | MEDIUM |
| SEC-0004 | leases optional; identity fully self-asserted | MEDIUM |
| SEC-0005 | `resource` field dropped on every production load path | HIGH |
| SEC-0006 | stale-rule ordering: idempotency is position-blind | MEDIUM |
| SEC-0007 | netns shares procfs/fs/IPC; creds in proxy environ | MEDIUM |
| SEC-0008 | unauthenticated credentialed proxy on 0.0.0.0 | HIGH |
| SEC-0009 | response trailers forwarded unscrubbed | MEDIUM |
| SEC-0010 | resource matcher raw-substring; userinfo/case/suffix/:443 bypasses | HIGH |
| SEC-0011 | unsigned receipt fields; pipe-canonicalization; in-memory nonces | MEDIUM |
| SEC-0012 | non-transit decision paths unreceipted | MEDIUM |
| SEC-0013 | FORWARD/IPv6/reused-network posture unasserted | MEDIUM |
| SEC-0014 | approvals not bound to exact request hash | MEDIUM |
| SEC-0015 | resolver path open; no deny-by-default resolver ships | INFORMATIONAL |
| SEC-0016 | self-minted approval → arbitrary `sh -c` on gateway host | **CRITICAL** |
| SEC-0017 | shipped configs open (0.0.0.0, no auth); config.Load fails open | **CRITICAL** (deployment-conditional) |
| SEC-0018 | flat single token = gateway root; no requester/approver split | HIGH |
| SEC-0019 | self-asserted identity → trust poisoning / evasion / flood | MEDIUM |
| SEC-0020 | policy takeover via candidate promote; admin audit-destruction | HIGH (open) / MEDIUM (token) |
| SEC-0021 | nonce cache global, in-memory, moot on unsigned requests | MEDIUM |

## 6. Mutated attacks (root-cause checks)

- Self-approval: loopback/bridge/veth/discovered-IP permutations all
  dead — fix addresses the path, not just the original port.
- Resource matching: 6 normalization mutations all bypass — the fix
  did NOT address root cause (parsed-vs-rendered mismatch) AND the
  field never reaches the matcher in production.
- Credential reflection: gzip mutation bypasses — scrub is byte-exact,
  not semantic. Encoding surface unbounded (base64/urlenc/rot13…).
- Decision parsing: 11 mutations incl. case/whitespace/truncation —
  all denied (fix is root-cause: explicit allow-only).
- Receipt integrity: mutation detection solid; **deletion family**
  (tail truncate, whole-file, rollback) all undetected — hash chain
  proves internal consistency, not completeness.
- Approval: state-transition mutations all rejected; request-substitution
  mutation open (no hash binding).

## 7. Boundary results

netns: **PARTIALLY VERIFIED** — egress/host-input verified closed;
caps/procfs/isolation gaps (SEC-0007); FORWARD unasserted (SEC-0013).
docker: **PARTIALLY VERIFIED** — icc/resolver/INPUT verified; stale-rule
ordering breaks liveness (SEC-0006); IPv6 NOT TESTED.

## 8. Credential results

**PARTIALLY VERIFIED** — injection+scrub works for exact bytes;
gzip/encoded/trailer surfaces leak; proxy itself is an unauthenticated
credential dispenser (SEC-0008); procfs env exposure in netns (SEC-0007).

## 9. Evidence results

**FAILED** as independently-verifiable evidence — chain detects
modification/reorder/mid-delete but NOT truncation/rollback/rewrite;
self-asserted pubkey accepted; anchors optional+unsigned+local;
unsigned fields; non-transit decisions unreceipted.
VERIFIED only as tamper-evident local log under a non-storage attacker.

## 10. Approval results

**FAILED** — live PoC: fabricated decision_id + caller `resource` →
self-approved → host `sh -c` executed (SEC-0016, CRITICAL). State
machine + auth-on-routes are sound, but the approval object isn't bound
to any real decision (SEC-0014) and one flat token does everything
(SEC-0018). In open deployments (SEC-0017) the whole chain is
unauthenticated remote RCE.

## 11. Identity results

**FAILED** as a security boundary — issuer registry itself verified
non-forgeable (caller keys never trusted, expired leases rejected), but
identity is fully self-asserted: leases optional (SEC-0004), subject_id
unauthenticated → trust poisoning/evasion/flood (SEC-0019).

## 12. Policy results

**FAILED** — resource scoping (the Phase-0 feature under test) does not
function on any production path; matcher itself unsafe even when field
loads. File-attack hardening verified closed.

## 13. Subagent findings (4 independent reviewers)

- **A (network)**: confirmed INPUT drops + icc work; found unauth proxy
  exposure (→SEC-0008), FORWARD/IPv6/reused-network gaps (→SEC-0013),
  position-blind idempotency (→SEC-0006), procfs sharing (→SEC-0007).
- **B (app/HTTP)**: found `:443` canonicalization + case/userinfo/
  substring bypasses (→SEC-0010), trailer leak (→SEC-0009), gzip
  surface (→SEC-0001); confirmed SSRF pinning + vhost-confusion fixes.
- **C (crypto/evidence)**: confirmed rewrite-resign + self-asserted
  pubkey (→SEC-0002), truncation (→SEC-0003); found unsigned fields,
  pipe-canonicalization, nonce replay, domain-separation gaps
  (→SEC-0011), unreceipted batch paths (→SEC-0012).
- **D (authz/policy)**: most severe report of the four. **Live-confirmed
  CRITICAL**: `approval/create` accepts fabricated decision_ids +
  caller `resource` → self-approve → unconditional host `sh -c`/`exec:`/
  `git:` executors (SEC-0016 — PoC ran on the audited deployment).
  Shipped `etc/config.json`/`sample_config.json` default to open
  0.0.0.0 no-auth and `config.Load` fails OPEN on missing file
  (SEC-0017). Flat single token = gateway root incl. the proxy's own
  gateway_token (SEC-0018). Policy promote/admin routes unauthenticated
  in open mode (SEC-0020). Self-asserted subject_id → trust poisoning/
  evasion (SEC-0019). Global in-memory nonce cache (SEC-0021). Also
  independently confirmed SEC-0004/0005/0010 and that min_trust_*
  fields are dropped alongside `resource`. Verified-good: approval/
  continuation state atomicity, policy path sandboxing, SSRF guard,
  lease crypto when present, sandbox defaults.

## 14. Conflicting findings

- Reviewer A rated unauth-proxy CRITICAL; audited as HIGH — reachability
  was deployment-conditional on THIS host (docker0 closed by ambient
  rules) though localhost confirmed. Severity kept HIGH: design flaw,
  environment-dependent exploitability.
- My earlier belief that `LoadStoreFromConfig` was reachable: WRONG —
  grep proved zero production callers; escalated SEC-0005 to HIGH.
- Resolver "OPEN" expectation in harness was a false FAIL (path open,
  no service) — corrected to informational.
- Reviewer D's RCE chain was initially a static claim — confirmed LIVE
  on the audited deployment (fabricated approval → `sh -c` wrote
  /tmp/cleanroom-pwn.txt), upgrading it from review-finding to
  demonstrated exploit.
- My earlier verdict on Attack 10 (PARTIALLY VERIFIED, "no agent-side
  replay exists") understated the case: the binding gap isn't just
  replay — the approval CREATE endpoint fabricates the decision side
  entirely. Upgraded to FAILED.

## 15. Remaining risks

- DNS covert channel whenever a resolver exists (SEC-0015).
- Encoding-surface credential leaks beyond gzip (SEC-0001 residual).
- Deployment-conditional proxy reachability (SEC-0008).
- Everything under "assumptions" in §3 is operator-enforced, not
  system-enforced.

## 16. Proposed fixes

All findings carry per-finding fixes in `security/findings/`.
Priority order for remediation: SEC-0005+0010 (unify parse paths +
component matcher), SEC-0008 (bind proxy + client auth), SEC-0001+0009
(full-surface scrub or strip encodings), SEC-0002+0003+0011 (receipt v2
+ required pubkey + signed anchors + seq), SEC-0006+0013 (assertive
firewall posture + doctor), SEC-0014 (request-hash binding), SEC-0004
(require leases where identity matters), SEC-0007 (uid separation +
doctor checks), SEC-0012 (gateway decision receipts), SEC-0015
(shipped resolver).

## 17. P1 readiness assessment

**NOT READY.**

The clean-room question — "can an intelligent adversarial agent bypass
Ovara?" — is answered YES on the tested build via at least three
independent routes:

1. **Policy bypass**: resource scoping is dead on every load path, and
   would be bypassable anyway (SEC-0005+0010). An agent allowed
   `http.request` has effectively unrestricted egress — credentialed.
2. **Credential exfil**: request `Accept-Encoding: gzip` (or any
   upstream transform) → injected credentials return to the agent
   intact (SEC-0001), or via trailers (SEC-0009).
3. **Evidence forgery**: any actor with write access to the evidence
   dir can rewrite+resign the whole chain and `ovara verify` reports
   valid (SEC-0002); tail deletion is invisible (SEC-0003).

4. **Gateway-root via approval API**: any holder of the single flat
   token (including the proxy itself) can mint+approve a fabricated
   `shell:` approval → `sh -c` on the gateway host — demonstrated live
   (SEC-0016). In shipped-config deployments the same chain is
   UNAUTHENTICATED remote RCE (SEC-0017). The boundary protects the
   *agent* from the gateway; nothing protects the gateway's own
   authority from its API callers.
5. **Policy takeover**: in open mode, `candidate/load`+`promote`
   replaces live policy unauthenticated (SEC-0020).

Additionally the unauthenticated credentialed proxy (SEC-0008) means
any process that can reach :9443 — confirmed for localhost — gets
credential injection attributed to the agent.

Phase-0 fixes that DO hold: boundary egress/host-input/L2 (tested
topologies), fail-closed decisions, CONNECT-deny evidence, approval
state machine, policy-file confinement, issuer registry, modification
detection in receipts.

P1 planning proceeds (plan document) — implementation must not start
until SEC-0001/0002/0003/0005/0008/0009/0010/0016/0017/0018/0020 are
remediated or explicitly accepted. The CRITICALs are cheap to gate
(bind approval-create to real decisions; fail closed on missing config;
ship authenticated defaults; split roles) and belong in the P1.0
remediation gate.

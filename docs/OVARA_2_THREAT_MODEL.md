# Ovara 2.0 — Threat Model & Security Assumptions

Status: RC1. The vocabulary used here (`BLOCKED / DETECTED / UNPROTECTED`)
is binding language for the implementation and docs — nothing gets called
"blocked" without an executable test. P1/P1.1 authorization-plane content
verified in the RC1 clean-room (`docs/OVARA_RC1_SECURITY_REPORT.md`).

## 1. Adversary

The adversary is autonomous software running inside the agent environment:

- full user-level code execution inside its environment (shell, file
  writes to *its* filesystem, process spawning, its own network stack
  usage within what the namespace allows)
- source-code-level knowledge of Ovara (assume it read the repo)
- unlimited patience; actively searching for bypasses; may attempt to
  destroy evidence, spoof identity, replay approvals, forge leases
- may be prompt-injected, compromised, or deliberately malicious

## 2. Trust boundary

```text
TRUSTED                              UNTRUSTED
─────────────────────────────────────────────────
host kernel                           agent process
host root / CAP_NET_ADMIN             agent's filesystem
proxy process memory                  agent's env vars
receipt signing key (var/)            agent's logs
policy/config files (host)            anything the agent can write
external anchor endpoint              agent-reported identity/time
```

Authorization-plane boundary (P1/P1.1):

```text
TRUSTED                              UNTRUSTED
─────────────────────────────────────────────────
gateway auth middleware               caller-supplied identity fields
credential-derived principal          agent_identity.subject_id claims
trusted_issuers registry (config)     client-supplied signatures/keys
issuer private keys (external)        delegation chain payloads
receipt/HMAC signing keys             lease fields before validation
evaluator decision path             request nonces, timestamps
host executor (opt-in only)           shell/exec/git resources pre-approval
```

The host's kernel and root are trusted **by assumption** — a host-root
adversary or kernel compromise is out of scope (higher threat tier; the
gVisor/Firecracker path exists for it).

### Assets

- Brokered credentials injected by the proxy (highest-value secret class)
- Operator/agent bearer tokens → derived principals
- Trusted-issuer private keys and the `trusted_issuers` registry
- Receipt signing keys (proxy ed25519 chain key, gateway HMAC key)
- Policy files, approval records, continuation state
- Evidence: receipt chains, event log, anchors
- Host executor integrity (opt-in `enable_host_executors`)

## 3. Security assumptions (testable preconditions)

| # | Assumption | If violated | Detectable? |
|---|-----------|-------------|-------------|
| A1 | Agent lacks CAP_NET_ADMIN | can rewrite routes/ifaces/nft → bypass | YES — integrity monitor (ruleset hash, iface scan) |
| A2 | Agent lacks CAP_NET_RAW | crafted non-TCP packets can skip rules | partially — CapEff scan |
| A3 | Agent lacks CAP_SYS_ADMIN | namespace escape → total bypass | YES — CapEff scan + ns checks |
| A4 | Agent lacks CAP_SYS_PTRACE | can inject into proxy process → creds+keys | YES — TracerPid watch |
| A5 | No docker socket in agent env | spawn sibling container → full host | YES — mount/socket check |
| A6 | Agent has no host root | everything | YES — euid check at launch |
| A7 | Host kernel honest | total bypass | NO — out of scope |
| A8 | Proxy/gateway process uncompromised | creds + signing key + CA all leak | partial — binary hash check possible |
| A9 | External anchor endpoint honest | history-rewrite detection lost | NO — accepted residual risk |
| A10 | DNS resolver deny-by-default | DNS exfil tunnel | NO — operator duty (documented) |

`ovara doctor` evaluates A1–A6 live; A7–A10 are documented, not
enforced. If any evaluated assumption fails →
`CONTAINMENT: NOT GUARANTEED`.

Authorization-plane assumptions (P1/P1.1):

| # | Assumption | If violated | Detectable? |
|---|-----------|-------------|-------------|
| B1 | `trusted_issuers` config maps only intended issuers to correct public keys | attacker-minted chains verify | config review — no runtime warning beyond "no issuers" |
| B2 | Issuer private keys stay external to the agent | full minting power under that issuer ID | NO — blast radius = issuer's own ID |
| B3 | Tokens are unguessable & agent-scoped for agents | principal theft | partially — violations logged as events |
| B4 | Gateway clock approximately correct | expiry checks meaningless | NO — standard NTP assumption |
| B5 | Replay window (5-min, in-memory) is acceptable | post-restart re-presentation of a valid chain | NO — documented limitation, not durable replay defense |
| B6 | `enable_host_executors` only set where host execution is intended | approved escalations run shell/exec/git on the gateway host | YES — config flag, logged loudly at startup |

## 4. Attack surface classification

| Channel | Classification | Mechanism |
|---|---|---|
| HTTPS via proxy | CONTROLLED | MITM + policy + injection + receipt |
| Direct IPv4 egress | BLOCKED | nft deny-all / --internal net — tested |
| Direct IPv6 egress | BLOCKED (netns: sysctl off; docker: v4-only bridge) | tested (netns) |
| QUIC/UDP443 | BLOCKED | drop (netns); unreachable (internal net) |
| Other UDP/non-DNS | BLOCKED | deny-all |
| TCP non-443 CONNECT | DENIED at proxy | port check |
| DNS to arbitrary resolver | BLOCKED | DNAT + only resolver:53 permitted |
| DNS tunnel via allowed resolver | UNPROTECTED-BY-DESIGN | resolver policy is operator's (A10) |
| WebSocket/Upgrade inside allowed conn | CONTROLLED (content opaque) | hop-header strip kills tunnel semantic — content still flows inside allowed conn |
| Encrypted payload to allowed host | UNPROTECTED | agent can always exfil to an allowed host's API (e.g. commit secrets to a repo it may push to). Mitigated by policy scope + sensitive_hosts escalation, not eliminated |
| Same-bridge L2 (docker) | UNPROTECTED | switched traffic bypasses iptables — keep bridge minimal (documented) |
| Reflective credential echo | CONTROLLED | `scrubReader` replaces injected secret values with `[REDACTED]` in upstream response bodies — verified live (RC1 e2e, httpbin echo) |
| Cert-pinned client | UNSUPPORTED | cannot MITM — agent's pinned connection fails closed (cannot connect) |
| SSH / DB wires | UNSUPPORTED | blocked at boundary; no data plane |
| Agent→agent comms via shared middlebox | UNPROTECTED-BY-DESIGN | classified, not blocked — sensitive_hosts policy is the control |
| Host services on non-proxy ports | BLOCKED | INPUT/DOCKER-USER port rules — tested |

Authorization-plane attack surface (P1/P1.1, all verified in RC1
clean-room unless noted):

| Channel | Classification | Mechanism |
|---|---|---|
| Caller claims `agent_identity.subject_id` ≠ credential principal | BLOCKED | `bindIdentity` → HTTP 400 + `security_violation` event — tested |
| Agent token on operator route | BLOCKED | `agentAllowed` allowlist → 403 — tested |
| Delegation: forged hop signature | BLOCKED | ed25519 vs `trusted_issuers` — tested |
| Delegation: untrusted intermediate | BLOCKED | every hop issuer must be registered — tested |
| Delegation: terminal subject ≠ principal | BLOCKED | binding check — tested |
| Delegation: scope/action amplification | BLOCKED | non-amplification + terminal capability check — tested |
| Delegation: replay in window | BLOCKED | signed-nonce key, dedicated cache, post-validation mark — tested |
| Delegation: replay after restart | UNPROTECTED-BY-DESIGN | process-local 5-min cache (B5) — documented |
| Delegation: empty audience | UNBOUNDED-BY-DESIGN | issuer's signed choice — valid at ANY gateway — documented semantics, verified at 2 gateways |
| Delegation: encoded path traversal (`%2e%2e`) | BLOCKED | decoded dot-segments rejected at shared canonicalizer — tested (RC1 gate fix) |
| Lease: foreign subject / wrong audience / expired / scope mismatch | BLOCKED | binding + exact-audience + scope checks — tested |
| Lease: empty audience | BLOCKED | lease audience must equal gateway identity (stricter than delegation) — tested |
| Approval: fabricated decision_id | BLOCKED | server-recorded decision required → 404 — tested |
| Approval: cross-principal create/read | BLOCKED | ownership → 403/404 — tested |
| Approval: agent token resolving | BLOCKED | operator-only → 403 — tested |
| Approval: resume replay | BLOCKED | single-use consume → 409 — tested |
| Denied/escalated action executing | BLOCKED | orchestrator only runs approved+queued continuations — tested (marker absent) |
| Internal `Evaluate` bypassing bindIdentity | PARTIAL | HTTP layer enforces binding; direct Go callers must supply a bound identity — documented |
| Trust containment (repeated violations) | BY-DESIGN | escalates subsequent requests — observed live, distinguish from direct deny |

## 5. Anti-forensics posture

- Evidence lives on the **host**, outside the agent's mount namespace —
  `rm receipts.jsonl` inside the agent can't reach it. (Correct by
  topology, not by file permissions.)
- Deleting host-side evidence requires host access = violates A6.
- Whole-file rewrite by the operator-class attacker is bounded by
  external anchoring: history diverges at last anchor → detected at
  verify time.
- Timestamp honesty: signer timestamps are proxy-generated (trusted
  domain). Agent cannot set them; a compromised proxy could backdate —
  mitigated by anchor timestamps (independent) — residual risk noted.

## 6. What Ovara does NOT defend (explicit)

- Host kernel compromise, host root attacker
- Side channels through allowed traffic content (steganography inside
  permitted API calls)
- Speculative/hardware attacks
- Availability of upstream services
- Agents colluding through an allowed third-party service
- Any claim that "isolation" makes a reachable-but-compromised service
  safe (the Artifactory lesson)

## 7. Claim discipline

Every public guarantee follows the format in SECURITY_CLAIMS.md:
mechanism + preconditions + evidence + known bypasses + status
(IMPLEMENTED/TESTED/LIVE VERIFIED/REVIEWED/PLANNED/NOT SUPPORTED).
Forbidden words unqualified: secure, safe, impossible, unhackable,
fully isolated, tamper-proof.

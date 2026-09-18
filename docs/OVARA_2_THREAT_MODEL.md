# Ovara 2.0 — Threat Model & Security Assumptions

Status: DESIGN. The vocabulary used here (`BLOCKED / DETECTED / UNPROTECTED`)
is binding language for the implementation and docs — nothing gets called
"blocked" without an executable test.

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

The host's kernel and root are trusted **by assumption** — a host-root
adversary or kernel compromise is out of scope (higher threat tier; the
gVisor/Firecracker path exists for it).

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
| Reflective credential echo | UNPROTECTED (to fix) | allowed reflector returns injected headers — needs response scrubbing |
| Cert-pinned client | UNSUPPORTED | cannot MITM — agent's pinned connection fails closed (cannot connect) |
| SSH / DB wires | UNSUPPORTED | blocked at boundary; no data plane |
| Agent→agent comms via shared middlebox | UNPROTECTED-BY-DESIGN | classified, not blocked — sensitive_hosts policy is the control |
| Host services on non-proxy ports | BLOCKED | INPUT/DOCKER-USER port rules — tested |

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

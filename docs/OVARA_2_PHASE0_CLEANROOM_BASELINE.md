# OVARA 2.0 — Phase 0 Clean-Room Baseline

Independent auditor baseline. Everything below was derived from the
implementation and live deployment, NOT from prior reports or docs.

## Tested commit

    7fc1b685463efc7828a34c5a1ff697c2a4040aa2
    "security: OVARA 2.0 Phase 0 — red-team reconciliation + confirmed fixes"
    Branch: feat/executor-proxy

`git status` during audit: clean except audit artifacts (this doc,
`security/findings/`, `tests/redteam/`, `loadpaths_test.go`).
No production files were modified during verification.

## Environment

| Item | Value |
|------|-------|
| Go | go1.25.6 linux/arm64 |
| Node | v24.21.0 |
| Kernel | Linux 6.17.0-1020-oracle aarch64 (Ubuntu) |
| Docker | 29.1.3 (sudo-required for CLI) |
| nft/iptables | sudo-only; inspected via privileged commands |
| User | ubuntu (uid 1001), sudo available |
| Test netns | `audit-ns`, subnet 10.200.188.0/24, gw .1 |
| Test docker net | `audit-egress`, 172.30.0.0/24, gw .1 |
| Gateway | 127.0.0.1:18080 (config `listen_addr` honored) |
| Proxy | :9443 all interfaces |
| Host INPUT | catch-all REJECT (pre-hardened, NOT default-ACCEPT) |
| Host FORWARD | policy DROP (ambient, not script-set) |

## What the implementation guarantees (verified)

1. **In-netns egress is deny-by-default.** nft `inet output` policy
   drop; only lo, established, proxy:9443, and DNS 53/5353 to the
   gateway IP are allowed; UDP/443 explicitly dropped.
2. **Host INPUT is closed for the agent's interface** (netns mode) —
   veth ingress accepted only for proxy port + DNS to gateway IP, then
   DROP. Verified against ssh, gateway port, random listeners.
3. **Docker same-bridge L2 is off** on created networks —
   `enable_icc=false` confirmed via network inspect + live
   agent→agent/agent→resolver probes failing.
4. **Gateway binds loopback** when `listen_addr: 127.0.0.1` is set
   (`ovara init` emits it) and requires auth (`auth_enabled: true`).
5. **Malformed/unknown gateway decisions fail closed** — 11 variants
   (empty, null, garbage JSON, wrong case, 500s, truncated) → HTTP 502
   + deny receipt.
6. **CONNECT-layer denials are receipted** — non-443, private, loopback,
   metadata, CGNAT targets each produced a `deny` receipt with target.
7. **Exact-byte credential scrub works** across headers, body, 1-byte
   split reads, large bodies, error pages — verified live through a TLS
   reflector and httpbin.
8. **Receipt tamper-detection works for modification/reorder/duplicate/
   mid-delete** — signature or chain-link failures on each.
9. **Approval state machine is atomic** — no double-approve, no
   resurrection after deny, unknown IDs 404, auth required.
10. **Policy file confinement works** — traversal, symlink escape,
    malformed JSON, out-of-dir candidates all rejected; bad loads don't
    displace the healthy policy.
11. **Dropped-capability agent cannot alter the boundary** — nft flush,
    route add, iface create all fail under `setpriv` caps.

## What the implementation does NOT guarantee (verified)

1. **Resource scoping** — `resource` field is dropped on every
   production load path (SEC-0005); matcher is raw-substring (SEC-0010).
2. **Proxy client authentication** — listener is unauthenticated on
   0.0.0.0; localhost reachability confirmed (SEC-0008).
3. **Credential secrecy under transformation** — gzip/encoded
   reflections leak secrets (SEC-0001); trailers unscrubbed (SEC-0009).
4. **Evidence completeness/external authenticity** — tail truncation
   undetected (SEC-0003); self-asserted pubkey accepted (SEC-0002);
   unsigned fields (SEC-0011).
5. **Non-network isolation in netns mode** — procfs/fs/IPC/unix shared;
   creds in proxy environ readable same-uid (SEC-0007).
6. **Firewall idempotency** — stale rules shadow new DROPs; script
   reports success on broken topology (SEC-0006).
7. **Host FORWARD/IPv6/reused-network posture** — unasserted (SEC-0013).
8. **Approval↔exact-request binding** — no request hash (SEC-0014).
9. **Receipt coverage of non-transit decisions** — gateway-only paths
   unreceipted (SEC-0012).
10. **Resolver safety** — path deliberately open, no deny-by-default
    resolver ships (SEC-0015).

## Assumptions the design relies on (not self-enforced)

- The agent runs with reduced caps (script prints `setpriv` guidance;
  doesn't enforce).
- The agent's uid differs from the proxy's uid (procfs creds exposure).
- Ambient host FORWARD posture is DROP or the agent subnet is
  unroutable beyond the host.
- The operator deploys a resolver that isn't an open relay.
- The boundary is created fresh (not on hosts with stale rules).

## Unknowns / not fully exercised

- Default-ACCEPT host FORWARD (this host was DROP) — asserted, not
  reproduced on a permissive host.
- Docker IPv6 enabled bridges — this environment is v4-only.
- DNS tunneling through a live resolver — no resolver was deployed.
- Concurrent receipt writes under multi-agent load.
- `unshare`/`setns`/AF_PACKET from inside netns — caps dropped in test
  but the boundary script doesn't enforce the drop.

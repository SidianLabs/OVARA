# OVARA-SEC-0008 — Unauthenticated credentialed proxy on 0.0.0.0

**Severity:** HIGH
**Component:** proxy/internal/proxy/proxy.go ServeHTTP,
proxy/cmd/ovara/main.go:296, config default `:9443`
**Status:** VERIFIED — fixed in P0.5 with live regression + clean-room replay (see docs/OVARA_2_P05_REMEDIATION_REPORT.md)

## Evidence
`ServeHTTP` performs no client authentication. The proxy listens on
`:9443` (all interfaces). Any caller that reaches it can CONNECT to a
bound host and get real credentials injected (policy allow decides — the
init policy allows `http.request`@dev).

Reachability verified: `127.0.0.1:9443` answers from any local process
(confirmed). docker0 → 172.17.0.1:9443 was closed on THIS host by
ambient DOCKER-USER/INPUT posture ("No route to host") — but that's
ambient luck, not design: on default-ACCEPT hosts, other bridges and
LAN hosts reach the injector. The INPUT DROPs only cover the agent's
own subnets (veth iface, 172.30.0.0/24).

## Root cause
The design assumed "only the agent reaches the proxy" — enforced only
for the scripted agent subnets, not for the proxy listener itself.

## Security impact
Any co-located process/container/peer gets credentialed egress to every
bound host, with receipts attributing it to "egress-agent" — indistin-
guishable from the real agent in evidence.

## Proposed fix (P1)
- Bind the proxy to the boundary address only (`10.200.x.1` /
  `172.30.0.1`), not `0.0.0.0`.
- AND require a per-agent/per-session execution-identity credential on
  every request (the P1 execution-identity primitive) — network
  reachability alone is not authentication.

## Regression test
Request from a non-boundary source (loopback, other bridge) must be
refused/401 before any credential injection.

## Residual risk
Until execution-identity lands, the shared token assumption means any
process able to reach the listener is trusted — must be documented
loudly in deployment docs.


## Remediation (P0.5 — VERIFIED)

`agent_token` in proxy.json authenticates proxy clients via Proxy-Authorization
(Basic or Bearer, constant-time compare). Unauthenticated requests are 407'd
before they reach the policy engine and leave a deny receipt. Startup refuses
an all-interfaces bind with no agent_token unless `unsafe_no_agent_auth=true`
is explicitly set. `ovara init` mints a distinct proxy client token; the
boundary script emits `http://agent:TOKEN@ip:port` proxy URLs automatically.
Shipped proxy.json binds 127.0.0.1.

Regression tests: `proxy/internal/proxy/sec0008_test.go`, `proxy/internal/config/sec0008_test.go`;
live replay: no token → 407, wrong token → 407, correct token → 200.

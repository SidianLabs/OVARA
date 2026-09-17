# Executor Proxy — Target Architecture

Status: **design direction for V2**. Not implemented in V1.0.0. This document
describes where Ovara is going and why; it is not a description of current
code.

## The Problem With Advisory Gateways

V1 is an advisory gateway: the agent (or its SDK) calls `/v1/runtime/check`,
receives allow/deny/escalate, and then executes the action itself. This is
cooperative enforcement — an agent that does not call the gateway, or ignores a
deny, is not constrained by it. The client-side interceptors
(`interceptors/shell`, `interceptors/git`) are wrappers the agent opts into.
eBPF monitoring observes but does not block.

This is documented here plainly because the honest property matters more than
the marketing one: **an advisory layer cannot stop a rogue agent. It can only
record one.**

## The Inversion: The Chokepoint Is the Notary

The fix is not more detection. It is moving authority out of the agent's
environment entirely:

1. **Credential starvation.** Real credentials (API keys, tokens, SSH keys)
   never enter the agent's process or environment. The agent holds only a
   short-lived capability lease and placeholder strings.
2. **The proxy is the executor.** The agent's environment has no usable egress
   except the proxy (network-namespace or VM boundary, default-deny). The agent
   sends an action request; the proxy evaluates policy, and on `allow` performs
   the call itself — injecting the real credential at the wire. On `deny` or
   `escalate`, nothing reaches the outside.
3. **Every transit is receipted.** Each request that crosses the proxy produces
   a signed, hash-chained receipt — including denied attempts. Because the
   proxy is the only path to a side effect, the receipt chain is not a log of
   what the agent claims to have done; it is a complete record of everything
   that touched the outside world.

The security property this buys: an agent going "rogue" produces only denied
requests — which are themselves receipted. Stopping power comes from
starvation; traceability comes free because the starvation point is also the
notary.

## Boundary Requirements

"Non-bypassable" is only real if the boundary is airtight. Minimum
requirements:

- Agent runs in its own network namespace or microVM; nftables default-deny
  OUTPUT except to the proxy; `CAP_NET_ADMIN`/`CAP_NET_RAW` dropped.
- All DNS redirected to a policy-enforcing resolver (deny-by-default), with
  resolved IPs pinned into the allow set — kills DNS exfiltration and
  direct-IP bypass.
- IPv6 ruled identically or disabled.
- SSH egress blocked or terminated at a bastion; git forced over HTTPS via
  `url.insteadOf` rewriting.
- TLS interception via a per-session CA installed in the guest trust store,
  or CONNECT-mode proxying where interception is not required.

## What Survives From V1

| V1 component | Role in V2 |
|---|---|
| Evaluator (identity → lease → drift → policy) | The proxy's per-request decision layer |
| CapabilityLease + trusted-issuer registry | The bearer token redeemable only at the proxy |
| Continuation state machine (escalate → approve → resume) | Async hold-and-resume for human approval on the hot path |
| Receipt pipeline | Becomes ed25519 per-action, hash-chained, externally anchored |
| Policy engine | Unchanged semantics; default escalate |
| eBPF monitor | Supplementary telemetry only |

## Honest Limits

- Protocol coverage is per-surface. HTTPS is cheap; git smart-HTTP is
  medium; Postgres/MySQL need bespoke data planes; SSH cannot be mediated
  inside the channel and must be blocked or bastioned.
- Hash-chained receipts prove the log was not modified — not that nothing
  bypassed the proxy. Completeness rests entirely on the boundary above.
- Local filesystem mutations do not transit a network proxy; they are
  covered by FS sandboxing plus snapshot/diff receipts, which are separate
  work.
- Human approval on the hot path requires the async continuation machinery
  already present in V1 — a blocking policy call is not sufficient.

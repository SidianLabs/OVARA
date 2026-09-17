# Executor Proxy — Deployment Guide

How to stand up the executor-proxy topology: the agent runs inside a
default-deny boundary, every side effect transits the proxy, and the proxy
receipts what crosses. This is the V2 direction described in
`docs/architecture/executor_proxy.md` — the boundary scripts and proxy
exist; treat per-protocol coverage as uneven.

## Architecture

```text
                    host (you control all of this)
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  ┌─────────────────────────┐      ┌──────────────────────────┐   │
│  │  agent environment      │      │  executor proxy          │   │
│  │  (container or netns)   │      │                          │   │
│  │                         │      │  • policy evaluation     │   │
│  │  agent process          │─────▶│  • credential injection  │──▶│ target APIs
│  │  no real credentials    │ :9443│  • receipt signing       │   │ github, etc.
│  │  placeholder tokens     │      │  • hash-chained log      │   │
│  │                         │      └──────────────────────────┘   │
│  │  nftables / internal    │                   ▲                  │
│  │  docker bridge:         │                   │ real creds live  │
│  │  default-deny OUTPUT    │                   │ here only        │
│  │  only -> proxy:9443     │      ┌──────────────────────────┐   │
│  │  :53 -> resolver        │─────▶│  deny-by-default DNS     │   │
│  │  IPv6 disabled          │ :53  │  (Corefile, allowlist)   │   │
│  └─────────────────────────┘      └──────────────────────────┘   │
│                                                                  │
│  kill switch: delete the credential binding row / proxy sidecar. │
│  agent starves instantly — it never held a usable credential.    │
└─────────────────────────────────────────────────────────────────┘
```

Boundary setup is in `proxy/scripts/setup-egress-boundary.sh` (netns and
docker modes). Resolver setup is in `proxy/scripts/resolver.md`.

## Trust store injection

The proxy TLS-intercepts agent traffic with a per-session CA. That CA must
be trusted inside the agent environment, per stack — there is no single
switch:

| Stack | Mechanism |
|---|---|
| OpenSSL / most C tools | `SSL_CERT_FILE=/path/to/ovara-ca.pem` |
| Node.js | `NODE_EXTRA_CA_CERTS=/path/to/ovara-ca.pem` (additive; does not replace system roots) |
| Python requests/httpx | `REQUESTS_CA_BUNDLE=/path/to/ovara-ca.pem` |
| git | `GIT_SSL_CAINFO=/path/to/ovara-ca.pem` or `git config http.sslCAInfo` |
| System-wide (Go, curl, most things) | copy CA into `/usr/local/share/ca-certificates/ovara-ca.crt`, run `update-ca-certificates` |

Practical approach: bake the CA into the agent image
(`/usr/local/share/ca-certificates` + `update-ca-certificates`), *and* set
the env vars anyway — some tools ignore the system store. For containers,
the env vars go on the `docker run` line next to `HTTPS_PROXY`.

Caveat: `NODE_EXTRA_CA_CERTS` is read once at process start; rotating the CA
requires restarting node processes. `SSL_CERT_FILE` *replaces* the default
bundle — point it at a file containing your CA **plus** the public roots,
or upstream verification of non-proxied hosts breaks.

## Known limitations

Stated plainly, same as the architecture doc:

- **Go CLIs on macOS.** Go binaries on macOS do not use the system keychain
  for verification the way you'd expect, and `SSL_CERT_FILE` behavior is
  build-dependent. Verify interception per-binary; don't assume the env
  vars covered it. (Unsure — behavior varies by Go version and whether the
  binary was built with `cgo`. Test yours.)
- **Certificate pinning.** Any client that pins certs/keys will fail closed
  under interception. That's correct behavior — but it means pinned clients
  can't be mediated this way. Either run them in CONNECT-only mode (no
  interception, metadata-only receipts) or don't run them.
- **QUIC/HTTP3.** UDP 443 is blocked at the boundary to force TCP fallback.
  Clients that hard-require QUIC or fail rather than fall back will break —
  which is the safe failure mode, but test your agent's HTTP stack.
- **SSH cannot be intercepted.** Block egress port 22 (the boundary
  default-deny already does). Git over SSH must be rewritten to HTTPS:
  `git config --global url."https://github.com/".insteadOf git@github.com:`.
  An agent that needs real SSH is outside this design — bastion it or deny.
- **gRPC.** Works at the TLS-transport level, but per-method policy is not
  implemented. Method-level interception is future work; today a gRPC allow
  is a channel allow.
- **The receipt chain proves the log, not the boundary.** Hash chaining
  proves receipts weren't modified. That nothing bypassed the proxy is a
  property of the boundary configuration — re-verify it when you change
  network topology.

## Kill switch

Stopping power is starvation, not detection. The agent holds a capability
lease and placeholder strings; the real credential lives only in the proxy's
credential binding.

- **Instant:** delete (or disable) the credential binding row for the
  agent/session. The next request through the proxy has nothing to inject —
  the agent's network still works, its authority is gone. No process kill,
  no teardown, no race with an in-flight action.
- **Hammer:** stop the proxy. The boundary is default-deny, so the agent's
  entire world becomes unreachable, including the proxy. Receipts stop
  being written — use this only when you want silence, not when you want a
  record of denied attempts.
- Denied requests still produce receipts. A "rogue" agent hammering the
  proxy generates evidence, not damage.

## Receipts verification flow

1. Every request that reaches the proxy — allowed or denied — produces a
   signed receipt (ed25519), hash-chained to the previous receipt.
2. To verify a chain: fetch the receipt log (`receipts_file` / equivalent
   export), recompute `hash(receipt_n) = H(receipt_n || hash(receipt_{n-1}))`,
   confirm each signature against the proxy's public key, and confirm the
   chain has no gaps.
3. Completeness argument: because the boundary is default-deny, any side
   effect that is *not* in the chain never happened. The chain is the full
   record — but only as strong as the boundary verification above.
4. External anchoring is implemented and env-configured: every
   `OVARA_ANCHOR_EVERY` receipts (default 1) the proxy appends
   `{"seq": N, "head": "<chain head hash>", "time": "..."}` to
   `OVARA_ANCHOR_FILE` (default `var/anchors.jsonl`) and optionally POSTs it
   to `OVARA_ANCHOR_URL`. For it to mean anything the sink must be outside
   the proxy host's blast radius — ship the anchor file off-box (object
   store, log aggregator, separate mount) or set the URL to a third-party
   collector. `-verify` checks each anchor's head against the recomputed
   chain head at that sequence and reports the first divergence.
5. Anchors prove the chain was not rewritten *after* each anchor — they do
   not prove completeness (that still rests on the boundary). Treat history
   before the first anchor as "tamper-evident, not anchored".

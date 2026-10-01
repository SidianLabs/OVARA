# Deny-by-Default DNS for the Egress Boundary

The egress boundary redirects all `:53` traffic to a resolver you control.
That resolver is part of the enforcement surface, not a convenience: if it
answers arbitrary queries, the agent has a working exfiltration channel
(DNS tunneling — data in QNAMEs/TXT answers — needs nothing but a resolver
that talks to the outside). A deny-by-default resolver that only resolves an
allowlist and returns `NXDOMAIN` for everything else collapses the channel
to a few bits of signal per denied query.

It also closes the quieter hole: direct-IP egress is denied by nftables, so
an agent that can't resolve names can't reach anything — which is the point.
Resolved IPs should be pinned into the proxy's upstream allow set, not into
the agent's.

## CoreDNS (recommended — small, single binary, Corefile is one file)

```corefile
# Corefile — deny-by-default forwarder for the boundary.
# Run on the resolver address your boundary script points at
# (e.g. 10.200.0.1:5353 in netns mode, 172.30.0.2:53 in docker mode).

# Allowlist: only these names resolve. Everything else falls through
# to the default server block and gets NXDOMAIN.
api.github.com github.com objects.githubusercontent.com {
    forward . 1.1.1.1 9.9.9.9
    log
    errors
}

# Catch-all: deny everything else.
. {
    # 'template' synthesizes NXDOMAIN for any query.
    template IN ANY {
        rcode NXDOMAIN
    }
    # Log denied lookups — they're signal (agent probing for egress).
    log
}
```

Run it:

```bash
docker run -d --name ovara-resolver \
  --network ovara-egress --ip 172.30.0.2 \
  -v "$PWD/Corefile:/Corefile" \
  coredns/coredns -conf /Corefile
```

Note: in `--internal` docker networks the resolver container itself still
needs outbound reachability for upstream `forward`. That means the resolver
container must sit on *two* networks (the internal bridge plus a normal
NAT'd one) or run on the host — a container on an internal-only network
cannot forward to `1.1.1.1`. This is easy to get wrong; verify with
`docker exec ovara-resolver nslookup github.com` before trusting it.

## dnsmasq (lighter, if you prefer)

```ini
# /etc/dnsmasq.d/ovara-boundary.conf
# Deny-by-default: only listed names resolve; everything else NXDOMAIN.
no-resolv
server=/github.com/1.1.1.1
server=/api.github.com/1.1.1.1
# dnsmasq quirk: without a catch-all server, unmatched names get REFUSED
# rather than NXDOMAIN. Both deny; REFUSED is arguably clearer in logs.
# To force NXDOMAIN semantics, use 'address=/#/' paired with explicit
# allows — but be aware that syntax footguns exist; test it.
log-queries
```

## Rules of thumb

- **Allowlist at the proxy, not the resolver.** The resolver's job is to
  keep the agent blind. Which hosts are actually *reachable* is the proxy's
  decision — keep both lists, keep them short, keep them separate.
- **Log denied queries.** A burst of NXDOMAINs is an agent probing the
  boundary. Route resolver logs to the same place receipts go.
- **TXT/ANY queries for allowed domains still exfiltrate.** If the allowlist
  is broad (e.g. `github.com` covers `*.github.com`? — no, CoreDNS zone
  matching is exact-suffix, so `evil.github.com` *would* match `github.com`;
  decide whether that's acceptable), a determined agent can stuff data into
  queries under allowed zones. The proxy sees the traffic anyway; the
  residual risk is small but real.
- **Don't run a general resolver.** Unbound/resolved defaults that recurse
  for anything are the failure mode this document exists to prevent.

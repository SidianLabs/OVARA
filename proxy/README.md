# Ovara Executor Proxy

The non-advisory half of Ovara: an egress chokepoint that **holds the
credentials, makes the decision, executes the call, and notarizes the
transit** — for any HTTPS API.

The agent's environment contains no real secrets and no usable egress except
this proxy (see `scripts/setup-egress-boundary.sh`). Every request is
evaluated against the runtime gateway (`allow`/`deny`/`escalate`); allowed
requests have real credentials injected at the wire and are executed by the
proxy itself. Every transit — including denied attempts — is appended to a
hash-chained, ed25519-signed receipt log verifiable offline.

```
agent env (no secrets, deny-all egress)
        │  CONNECT api.x.com:443
        ▼
┌─ ovara-proxy ────────────────────────────────┐
│ MITM (per-session CA)                         │
│ → gateway check: http.request, METHOD URL     │
│ → allow: inject real creds, execute upstream  │
│ → deny/escalate: 403, receipted anyway        │
│ → append hash-chained ed25519 receipt         │
└──────────────────────────────────────────────┘
```

## Universal by design

No per-provider adapters. One config block covers any HTTPS API:

```json
{"host": "api.anthropic.com",
 "headers": {"x-api-key": "${ANTHROPIC_API_KEY}"}}
```

Host globs (`*.slack.com`) match subdomains. Secret values are expanded from
the **proxy host's** environment — the agent only ever sees placeholders.
Deleting a binding is the kill switch: the agent keeps running and is
instantly powerless.

## Run

```bash
go build -o ovara-proxy ./cmd/ovara-proxy
# gateway must be running and reachable at gateway_url
./ovara-proxy -config etc/proxy.json
# point the agent env at it:
export HTTPS_PROXY=http://proxy:9443
# trust the generated CA (var/ca.pem) in the agent trust store
```

## Verify a receipt chain (offline, third party)

```bash
./ovara-proxy -verify var/receipts.jsonl -pubkey $(cat var/receipt.pubkey)
# {"total": N, "valid": true}
```

## Honest limits

- **HTTPS only.** SSH, database wire protocols, gRPC need bespoke data
  planes (see docs/architecture/executor_proxy.md). Block SSH; force git
  over HTTPS.
- The chain proves the log wasn't modified — completeness rests on the
  egress boundary being airtight (`scripts/` + `DEPLOYMENT.md`).
- MITM needs the per-session CA trusted inside the agent env; tools with
  real cert pinning can't be intercepted (SNI-level policy only, or deny).
- `fail_open: true` exists for development and voids the guarantee.

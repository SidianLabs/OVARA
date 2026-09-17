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
# with anchors present: {"total": N, "valid": true, "anchors": M, "anchors_valid": true}
```

## External anchoring (anti-rollback)

Signatures prove receipts weren't modified; they do *not* prove the proxy
didn't discard the log and rewrite history with the same key. Anchoring
closes that gap: every `OVARA_ANCHOR_EVERY` receipts (default 1), the proxy
writes `{seq, head, time}` — sequence count, chain head hash, timestamp — to
an external sink:

- `OVARA_ANCHOR_FILE` — JSONL append path (default `var/anchors.jsonl`).
  Put it on a different host/mount/object store than the receipts, or it
  proves nothing.
- `OVARA_ANCHOR_URL` — optional; the same anchor is POSTed as JSON
  (fire-and-forget, 5s timeout). Point it at anything that timestamps and
  retains: a log service, a transparency-log shim, an internal append API.

`-verify` picks up the anchor file automatically (`OVARA_ANCHOR_FILE` or
the default path) and checks each anchor's `head` against the recomputed
chain head at that `seq` — first divergence flips `valid` to false.

## Honest limits

- **HTTPS only.** SSH, database wire protocols, gRPC need bespoke data
  planes (see docs/architecture/executor_proxy.md). Block SSH; force git
  over HTTPS.
- The chain proves the log wasn't modified — completeness rests on the
  egress boundary being airtight (`scripts/` + `DEPLOYMENT.md`).
- Anchors prove the chain wasn't rewritten *after* each anchor — and only
  if the sink is genuinely outside the proxy's control. History before the
  first anchor is still "tamper-evident, not anchored".
- MITM needs the per-session CA trusted inside the agent env; tools with
  real cert pinning can't be intercepted (SNI-level policy only, or deny).
- `fail_open: true` exists for development and voids the guarantee.

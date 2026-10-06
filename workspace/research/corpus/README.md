# v1 behavioral corpus

Purpose: recorded request→response pairs through the live gateway for
differential testing (v1 vs v2 on the same input matrix).

- `collect.py` — the matrix + collector (stdlib-only, deterministic
  row ids; nonces/issued_at generated at run time).
- `v1_baseline.jsonl` — 45 rows captured 2026-10-06 against
  `ovara run` on `workspace/env/v1corpus` (policy: `http.request` allow
  in dev + `*` escalate catch-all; auth on; host executors off).

## Reproduce

```bash
go build -o /tmp/ovara ./proxy/cmd/ovara   # from repo root proxy/
/tmp/ovara init workspace/env/v1corpus
/tmp/ovara run -dir workspace/env/v1corpus &   # gateway :8080
TOKEN=$(python3 -c "import json;print(json.load(open('workspace/env/v1corpus/config.json'))['agent_tokens'][0])")
python3 workspace/research/corpus/collect.py http://127.0.0.1:8080 "$TOKEN" out.jsonl
```

The env dir is git-ignored and regenerable via `ovara init` (values
differ per init — re-collect after re-init).

## Observed baseline behaviors (from v1_baseline.jsonl)

| Behavior | Evidence |
|---|---|
| Fresh deployment escalates EVERYTHING: seeded agent principal has trust `none` → `restricted` → `containment_active` escalate (35/45 rows incl. the dev `http.request` allow rule — restriction dominates policy allow, runs at evaluator step 5) | rows action-*, env-* |
| `agent_identity.subject_id` must equal the credential-derived principal (`ag_<sha256[:16]>`); mismatch → HTTP 400 `identity_mismatch` (not a 200 deny) | ident-present, lease-bogus, chain-bogus |
| Replay (same nonce) → deny `action_not_allowed`; stale/future issued_at → deny; huge min_epoch → deny `revocation_epoch_stale`; missing nonce/resource → deny | replay-2, stale/future-issued, min-epoch-huge, missing-* |
| `action_type` is an open string — `http.request` (not in the 14-type enum) evaluates fine; no closed vocabulary at the schema edge | env-*-http rows |
| Decision 200s always; auth/identity failures are HTTP 400 — two error planes | whole file |

Corpus gaps to fill later: signed-lease happy path (needs a lease
minted under a configured trusted issuer), approval-lifecycle rows
(create→approve→resume), continuation rows, production env with an
explicit allow rule, trust-score variance over repeated risky actions.

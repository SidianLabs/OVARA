# v1↔core corpus differential

Replayed `v1_baseline.jsonl` (45 recorded live decisions) through the
redesigned pipeline (`runtime/gateway/tests/differential/corpus_test.go`,
asserted against the security-correct outcome per row, not v1's).

Reference policy: allow http/net to `https://api.github.com*`; deny
metadata IP + fs.delete; escalate shell.exec/proc.spawn/git.push;
default deny.

| Row | v1 | core | Note |
|---|---|---|---|
| action-shell | escalate | escalate |  |
| action-exec | escalate | escalate |  |
| action-git.push | escalate | escalate |  |
| action-git.pull | escalate | deny |  |
| action-git.fetch | escalate | deny |  |
| action-git.checkout | escalate | deny |  |
| action-git.force_push | escalate | escalate |  |
| action-github.push | escalate | deny |  |
| action-github.pr | escalate | deny |  |
| action-github.merge | escalate | deny |  |
| action-github.delete_branch | escalate | deny |  |
| action-ci.deploy | escalate | deny |  |
| action-ci.build_trigger | escalate | deny |  |
| action-ci.approval | escalate | deny |  |
| env-local-shell | escalate | escalate |  |
| env-local-http | escalate | allow |  |
| env-dev-shell | escalate | escalate |  |
| env-dev-http | escalate | allow |  |
| env-staging-shell | escalate | escalate |  |
| env-staging-http | escalate | allow |  |
| env-production-shell | escalate | escalate |  |
| env-production-http | escalate | allow |  |
| res-userinfo | escalate | deny (parse) | userinfo rejected at canonicalize — v1 evaluated it |
| res-suffix | escalate | deny | host-boundary: no suffix-append match (SEC-0010) |
| res-notgithub | escalate | deny |  |
| res-metadata | escalate | deny |  |
| res-port | escalate | allow | default port stripped → allow match |
| res-explicit80 | escalate | deny |  |
| res-noscheme | escalate | deny (parse) | missing scheme rejected at parse |
| res-risky-rm | escalate | escalate |  |
| res-risky-curl | escalate | escalate |  |
| res-empty | deny | deny (parse) |  |
| ident-present | HTTP 400 | escalate | wire identity ignored; credential-derived actor — spoof neutralized |
| ident-empty-key | escalate | escalate |  |
| lease-bogus | HTTP 400 | deny |  |
| lease-bogus-noident | escalate | escalate |  |
| chain-bogus | HTTP 400 | deny |  |
| replay-1 | escalate | escalate |  |
| replay-2 | deny | deny (replay) | crypto-real replay deny (sig covers nonce) |
| stale-issued | deny | deny |  |
| future-issued | deny | deny |  |
| min-epoch-1 | escalate | escalate |  |
| min-epoch-huge | deny | deny | min_epoch beyond current → deny |
| missing-nonce | deny | deny |  |
| missing-resource | deny | deny (parse) |  |

## Result

45/45 rows produce the annotated core outcome. Divergence classes vs
v1: (1) **stricter-by-default** — v1's containment escalated git.pull/
github.*/ci.*; core denies what policy doesn't cover. (2) **parse-time
rejects** — userinfo, missing scheme, empty resource never reach the
evaluator. (3) **identity spoof neutralized** — wire subject ignored;
v1 rejected with 400, core simply doesn't honor it. (4) **crypto-real
replay/freshness** — signatures cover nonce+issued_at.

## Found while building this (now fixed)

- `policy.matchPatterns`: trailing-`*` patterns like
  `https://api.github.com*` string-prefix-matched
  `api.github.com.evil.com` — SEC-0010 class leak. Fixed: star after
  a bare host now means "this exact host, any path".

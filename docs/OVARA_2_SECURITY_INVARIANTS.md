# Ovara 2.0 — Security Invariants

Status: DESIGN. Each invariant gets an executable test in
`tests/security/` (Go) or the redteam harness — an invariant without a
test is a wish, not a guarantee. Current test status is noted.

## I1 — Mandatory egress
> An agent inside the boundary cannot establish external network
> connectivity except through the Ovara proxy.

Test: `tests/boundary/netns_test.sh`, `tests/boundary/docker_test.sh` —
deploy the real boundary and assert from inside: proxy port reachable,
non-proxy host/gateway port unreachable, direct external egress denied,
IPv6 disabled (netns). Scripts SKIP (exit 77) when prerequisites
(root/nft/docker) are absent — a skipped environment is not a pass.
**Status: LIVE-ENVIRONMENT VERIFIED** — netns 4/4 and docker 3/3 ran
green against a real deployed boundary in the post-review environment.
The property remains deployment-bounded: the software ships the
boundary script and the test; enforcement exists only where an
operator has actually applied it.

## I2 — Credential custody
> The agent cannot obtain a brokered credential.

Test vectors: reflector echo (httpbin /headers — **closed**: the response
scrubber replaces injected secret values with `[REDACTED]` — verified
live in the RC1 clean-room), redirect leakage, error-page leakage,
/proc inspection, env inspection, receipt inspection, log inspection.
**Status: TESTED** — custody-by-construction + response scrubbing
verified live (RC1 e2e harness, `injected credential echoed by
upstream → [REDACTED]`).

## I3 — Complete evidence
> Every request that transits the enforcement point produces an evidence
> event — including denials, escalations, errors, and client aborts.

Test: induced failures at each stage; verify receipt exists for each
(unreceipted-transit = invariant violation).
**Status: IMPLEMENTED** — abort-after-upstream edge case needs a test.
Post-review hardening (F-01): a failed `receiptsStore.Put` now emits
`receipt.persist_failed` (never `receipt.issued`) and logs a SECURITY
line — a missing receipt can no longer masquerade as persisted.
Covered by `internal/handlers/receipt_persist_test.go`.

## I4 — Denied cannot execute
> A `deny` decision cannot result in upstream execution, and a denied
> continuation cannot be resurrected by a later approve.

Test: concurrent approve/deny race, replayed deny, stale approval.
**Status: TESTED** (atomic Resolve/ApplyApprovalDecision).

## I5 — Approvals are single-use and bound
> An approval bound to request X cannot resume request X' or be reused.

Extension required: bind canonical request-hash + policy_version into
the approval record and the resume token.
**Status: PARTIAL** (single-use done; request-hash binding new).

## I6 — Policy is agent-immutable
> Policy files are outside the agent's reach; the policy API rejects
> reads/writes outside policy_dir (incl. symlink escapes).

**Status: TESTED** (EvalSymlinks confinement).

## I7 — Evidence is agent-immutable
> Evidence lives on the host; the agent cannot reach, modify, or delete
> it; chain verification detects modification/deletion/reorder.

**Status: TESTED** (host-side placement + chain verify); anchor-based
deletion-detection partial.

## I8 — Bypass attempts are observable
> Boundary manipulation (routes, ifaces, nft, resolver, Ovara processes)
> is detected (host-side integrity monitor) and emits a
> `boundary_violation` event; where capabilities allow prevention, it is
> prevented by capability absence — never relied on agent cooperation.

**Status: NEW** (integrity monitor not yet built).

## I9 — Honest coverage
> No channel is represented as controlled unless it is tested. The
> doctor/status output distinguishes CONTROLLED / BLOCKED /
> UNPROTECTED / UNSUPPORTED.

**Status: process invariant — enforced via claims doc + scorecard.**

## I10 — Fail closed on security-relevant failure
> Gateway unreachable, missing trusted issuers, corrupt chain, empty
> operator tokens, malformed decision → deny/abort, never silent-allow.
> `fail_open`/`allow_unsigned_leases` are explicit dev flags that print
> loud warnings.

**Status: TESTED.**

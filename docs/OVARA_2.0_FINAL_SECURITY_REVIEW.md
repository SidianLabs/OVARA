# OVARA 2.0 — Final Independent Security Review

Reviewer: independent adversarial pass over the merged security
architecture (RC1 → P2.1 → P2.2 → P2.3.1–P2.3.6). Code is treated as
authoritative; documentation was used only to derive claims to test.

## 1. Executive Summary

The OVARA 2.0 gateway enforces its documented authorization boundary:
every path that reaches an executor passes through authentication,
policy evaluation, an atomic claim transition, and claim-time authority
revalidation. No route, retry path, recovery path, or planted record was
found that reaches an executor without that boundary — **within the
documented trust-domain assumption** (the agent cannot write gateway
persistence files).

All 376 frozen regression checks pass (10 harnesses, RC1–P2.3.6). The
independent adversarial harness executed 29 scored checks; the single
non-pass was a harness parsing artifact — the journal showed the
documented behavior occurred correctly (a queued continuation executed
after its credential was revoked, which is the specified semantic).

No CRITICAL or HIGH authorization bypass was found. The meaningful
residuals are: the physical egress boundary is a deployment property,
not a software property; execution-side persistence lacks the
hash-chain integrity the trust journals have; receipt persistence
failure can produce a false `receipt_issued` event; and credential
revocation does not freeze already-queued work (identity suspension
does — documented).

**Status: FINAL SECURITY REVIEW — PASS WITH DOCUMENTED LIMITATIONS.**

## 2. Review Scope

In scope: `runtime/gateway` (all handlers, evaluator, continuation,
execution, receipt, revocation, gwidentity, anchor, policy, auth,
idregistry, replay stores), `pkg/server` wiring, the egress boundary
script, SDK/proxy surfaces as they relate to boundary claims, and all
security documentation's testable claims.

Out of scope (stated by docs, verified as absent rather than claimed):
distributed/multi-oracle replication, TPM/hardware key roots,
agent-enclave attestation, gRPC per-method policy, SSH interception.

## 3. Repository/Commit Baseline

```
branch:       main
HEAD:         93e2469 (== origin/main)
reachable:    P2.3 merge 5da517e, core f864ea0, RC1/P2.1/P2.2 lineage
working tree: NOT clean — M .github/workflows/docker.yml,
              M .github/workflows/lint.yml
```

The two modified files are CI workflow edits that cannot be pushed with
the current OAuth token (missing `workflow` scope). They are non-
security, non-production files; the reviewed artifact (`HEAD`) is
unambiguous. Declared exception to the clean-tree requirement —
reviewed code is exactly `origin/main`.

## 4. Threat Model

Adversary assumed: full agent control; arbitrary action/resource
requests; forged caller identity fields; revoked/rotated credentials;
controlled delegation issuers and intermediate keys; replayed
presentations, approvals, leases; local persistence manipulation;
arbitrary process kills; journal truncation/modification/snapshot
restore; cross-domain and cross-gateway artifact injection;
executor/proxy bypass attempts; race exploitation.

Explicitly out (per `docs/OVARA_P2.3_THREAT_MODEL.md`, assumption A6):
host-root attackers and writers to the trust-domain state files. All
findings below respect that boundary and label anything requiring it
as ARCHITECTURAL LIMITATION, not a claim violation.

## 5. Security Architecture

Request path verified end-to-end:

```
bearer token → middleware (registry.Authenticate → stable identity)
  → role gate (agent allowlist: 5 routes; all else operator-only)
  → evaluator (policy → delegation chain → revocation → replay → lease)
  → decision + receipt stub → recordDecision (log/receipt/events/cache)
  → (escalate) approval create (server-side provenance rebuild)
  → operator approve → continuation approved→queued
  → ClaimForExecution (atomic state transition, persisted)
  → CheckClaimAuthority (lease + delegation keys + issuers revalidated)
  → executor (shell/exec/git.* host executors, optional sandboxed)
```

Executor call sites: exactly two — sync execute and orchestrator
drain — both behind claim→authority. Retry/enqueue/resume/recovery
paths all reconverge on `ClaimForExecution`.

## 6. Authentication/Identity Review

- Principal identity is derived from the credential record
  (`idregistry.Authenticate`), never from caller JSON.
  `AgentIdentity.SubjectID` is overwritten server-side from
  `ctxKeyPrincipalID`.
- Unknown, revoked, superseded, expired, suspended → 401. Verified
  live (FR-D: revoked credential → 401 on new requests).
- `auth_enabled=true` with no tokens → deny-all (not open). Misconfig
  guard present and correct.
- `whoami` returns only the caller's own principal.
- Identity suspend/retire are operator-gated transitions persisted in
  the registry; retirement survives restart.
- Credential revocation and identity suspension are distinct controls
  with distinct effects (see §8).
- Token comparison uses `subtle.ConstantTimeCompare`.

**Result: PROVEN** within the software-token model (bearer tokens, not
hardware-rooted — documented D-08).

## 7. Delegation Review

Chain validation order in the evaluator is correct: signature → issuer
trust → revocation → replay → linkage → narrowing → audience → expiry.
Verified:

- Hop removal, reorder, duplication, issuer/subject/audience
  substitution → rejected (p234 harness, 44/44).
- Scope widening at an intermediate hop → rejected (containment is
  canonicalized both directions).
- Cross-domain and cross-gateway presentations → rejected on audience
  binding (FR cross-domain checks).
- Replayed chain / replayed nonce → rejected while replay journal
  exists.

Canonicalization (`policy.CanonicalResource`, `MatchCanonicalResource`)
was probed with 18 evasion inputs: `%2e` traversal, encoded separators,
userinfo, scheme tricks, host-label confusion (`github.com.evil.com`,
`evilgithub.com`), trailing dots, double slashes, query/fragment
smuggling, port range tricks, backslash, percent-encoded literals —
**all fail closed**. Wildcard host matching enforces proper subdomain
boundaries. The same canonicalizer serves policy match, scope
containment, and lease checks — no validation/execution divergence
found.

**Result: PROVEN** for the URL forms accepted; malformed forms are
denied, not partially matched.

## 8. Lease/Revocation Review

- Lease signature, subject, audience, expiry verified; malformed or
  foreign leases denied (p234).
- Claim-time revalidation: `RevocationPairs()` on the continuation
  returns captured `lease_id`, delegation presentation keys, and
  issuer IDs; `CheckClaimAuthority` revalidates each against current
  revocation state before the executor runs.
- **Demonstrated:** planted queued continuation carrying a revoked
  lease → `executing → denied` at claim (FR-C). The revocation check
  fires even for records that bypassed normal creation.
- Credential revocation is **not** a claim-time pair (documented
  D-11/D-12 scoping). Demonstrated: continuation queued under a
  credential still executed after that credential was revoked (FR-D2).
  New authentication under the revoked credential → 401. The freeze
  control for queued work is **identity suspension**, which was
  verified to block claiming.

**Result: PROVEN** as specified. The credential-revoke/queued-work
semantic is an explicit documented limitation, restated in §23 so it
cannot be over-read.

## 9. Approval/Continuation Review

Approval creation (`handleCreate`) is fully server-bound:

- `decision_id` must resolve through the decision provenance cache —
  fabricated IDs → 404 + security event (`fabricated_decision`).
- Only the decision's owning principal (or an operator) may create —
  cross-principal → 403 + event.
- Caller-supplied action/resource/agent fields that diverge from the
  recorded request → 400 + event (`approval_field_tamper`).
- The approval is rebuilt entirely from server-recorded state;
  `RequestHash` (receipt action digest) and `PolicyVersion` are bound
  into the record — I5's "required extension" is implemented (the
  invariant doc's "PARTIAL" status is stale).
- Idempotent per decision: pending/approved returns the existing
  record; denied → 409 (no second bite — approval-fatigue defense).
- Escalated decisions only; approving a non-escalated decision → 409.

Continuation creation captures lease ID, delegation keys, and issuers
from the *evaluated request*. Nothing in the continuation accepts
caller-supplied authority.

**Result: PROVEN.**

## 10. Claim/Execution Review

- `ClaimForExecution` is atomic: state transition to `executing` is
  persisted before return; a second claim fails. `isClaimable` =
  {approved, queued, resumed} and unexpired.
- `denied`, `expired`, `cancelled`, `executed` records cannot be
  claimed or resurrected (I4 verified — denied continuations cannot be
  re-approved into execution; approve on resolved → conflict).
- Executor surface: `shell`, `exec`, `git.push/pull/fetch/checkout`
  host executors (when `enable_host_executors`), optional
  `shell.sandboxed` (docker). `shell:` resources run `sh -c` on the
  gateway host — correctly gated, but powerful; see §16/§23.
- Single-use resume token consumed on resume; revoked-authority resume
  does not consume the token (operator can retry after store recovery).

**Result: VERIFIED.** The claim boundary holds under restart,
orchestrator drain, operator sync-execute, retry, and resume.

## 11. Persistence/Crash Review

- Registry, replay, anchor stores: append journals with flock,
  fsync-on-commit, hash-chained records, corruption → fail-closed at
  open (`OpenFile` refuses).
- Demonstrated: mid-chain registry tamper → startup refuse (FR-G);
  tail truncation → refuse (strict) or anchor-detected.
- Continuation/execution stores: append JSONL, mode 0644, **no
  integrity chain**. Store loads once at `Open`; appends are invisible
  to a running process.
- Demonstrated: a planted `state:"queued"` continuation line executes
  after restart (FR-A, FR-K — claimed, authority-checked, executor
  ran). A tampered `resource` field is executed as recorded.
- This is inside trust-domain assumption A6 (agent cannot write these
  files) — recorded as finding F-03 because the asymmetry with the
  hash-chained trust journals means silent-vs-detected tamper differs
  by store.

## 12. Journal/Rollback Review

- Hash chain detects mid-chain modification and insertion (startup
  refuse).
- Tail truncation: refused outright in strict anchor mode; detected via
  oracle checkpoint comparison when anchoring configured.
- Replay-journal deletion → nonce reuse possible (FR-J). Documented
  local-journal rollback residual — the replay store is a local
  journal, not externally anchored; the claim is scoped accordingly.
- Old-prefix/snapshot restore of the registry alone → chain still
  verifies (it is internally consistent) but anchor reconciliation
  refuses L<A (local behind oracle). Verified the frozen table.

## 13. Anchor/Oracle Review

- `reconcileAnchor` enforces the frozen table: L<A refuse; L==A same
  tip accept; L==A different tip refuse (equivocation); L>A refuse in
  strict — **never auto-pushes a local-ahead tail** (a forged tail
  cannot crown itself); empty journal refuses in strict.
- `anchor_catchup=auto` controls availability tolerance only; it is
  ignored in strict and never escalates authority (verified in code).
- Oracle transport: `unix://` uses SO_PEERCRED UID pinning; `https://`
  uses Ed25519 public-key-pinned mTLS. No unauthenticated path.
- Anchor store: serialized mutate, monotonic sequence, same-seq
  equivocation detection, flock. Checkpoint signature authenticates
  the writer; the monotonic store decides authoritative advance —
  neither alone claims journal truth (correct design).
- Documented residual confirmed as documented: joint registry+oracle
  rollback is the trust-root/backup compromise case, not claimed
  preventable.

**Result: VERIFIED** under single-oracle scope (replication
unimplemented — D-13).

## 14. Cross-Domain Review

Audience binding enforced on leases, delegations, approvals,
continuations; the gateway registry is keyed `(gateway_id, key_id)` —
foreign keys are unresolvable; the anchor pin binds the oracle
identity. Tested: foreign-domain artifacts and wrong-audience
presentations → rejected (FR cross-domain checks; p233/p234 suites).

**Result: PROVEN.**

## 15. Receipt Review

`edsigner.go`: domain-separated (`OVARA-RECEIPT-SIG-V1`), `edsig_v1:`
prefix, `SignedPayload` covers every authoritative field including the
inner HMAC, fixed-order length-prefixed encoding, issued-at in ns.
`GatewayID`/`GatewayKeyID` stamped before signing. Verification
resolves the public key from the registry by `(gateway_id, key_id)` —
caller-supplied keys are never consulted; revoked/superseded keys still
verify historical receipts (correct semantics); missing registry →
`ErrNoRegistry`; malformed → invalid (p235, 43/43).

Non-claims (verified as documented): a valid receipt does not prove
execution truth, completeness, or immutable history; `trust_epoch` is a
local monotonic sequence, not global consensus.

**Result: PROVEN** under software-key model.

## 16. Network/Executor Boundary Review

**What OVARA software enforces:** the proxy authenticates to the
gateway, brokered credentials are injected upstream and scrubbed from
responses (custody-by-construction + `[REDACTED]` — verified RC1), all
decisions transit the gateway.

**What deployment must enforce:** that the agent cannot reach the
network except through the proxy. `proxy/scripts/setup-egress-boundary.sh`
implements this correctly: dedicated netns (or docker net), nftables
default-deny OUTPUT, DNS redirected to the proxy resolver, UDP/443
dropped (QUIC), only the proxy port reachable. A malicious agent that
can open a raw socket *inside an unbounded network* bypasses nothing —
there is nothing to bypass; the software assumes the boundary exists.

I1 is therefore an **architectural limitation**: a deployment property,
honestly documented ("The receipt chain proves the log, not the
boundary"). Finding F-02 records that the referenced live boundary
tests are absent from the tree.

Host executors (`shell`, `exec`, `git.*`) run on the gateway host —
`shell:` executes `sh -c`. Optional `shell.sandboxed` runs under
docker. Enabling host executors is a documented, loud-logged config
choice; the executor surface is itself the trust decision.

## 17. Configuration/Fail-Closed Review

- `auth_enabled=false` → open mode, loudly logged; `unsafe_no_auth`
  refuses non-loopback binds.
- `anchor_mode` unknown value → refuse; `strict`/`degraded` semantics
  match docs; `catchup=auto` never escalates.
- `enable_host_executors` logs the enabled surface explicitly.
- `gateway_key_grace_seconds` >24h → refuse.
- Corrupt registry/replay/anchor files → fail-closed at open.
- No silent degraded path found: every optional mode logs or refuses.

**Result: VERIFIED.**

## 18. Alternate Entry Point Review

Route inventory: ~65 registered routes. Agent-reachable: exactly 5
(`POST /v1/runtime/check`, `POST /v1/runtime/batch-check`,
`POST /v1/approval/create`, `GET /v1/approval/{id}` except `/pending`,
`GET /v1/whoami`). Everything else is operator-only **by default** —
new routes are operator surfaces unless deliberately allowlisted
(fail-safe direction). Unauthenticated: `/health`, `/ready` only;
`/v1/runtime/status` deliberately requires auth (discloses paths,
counts, identity).

Tested live (FR-E): agent token → 403 on continuations, revocations,
identities, executions, events, receipts, runtime/status, admin.
`GET /v1/approval/{id}` enforces ownership with 404 (no existence
oracle). Enrollment is a local file service — no HTTP trust-bootstrap
endpoint on the gateway.

**Result: PROVEN.**

## 19. Credential Exposure Review

- No token/secret/private-key values in logs (swept all `log.*` sites).
- `whoami` reveals only own identity; `identities` list returns
  fingerprints, not tokens (operator route anyway).
- Server-generated tokens returned once at register/rotate.
- Upstream-injected secrets scrubbed from responses — RC1-verified
  (`[REDACTED]`); encoding transforms don't bypass since scrubbing is
  value-substitution on the body.
- Gateway private key: file 0600, atomic write, corrupt → reject.

**Result: VERIFIED.**

## 20. Operator/Agent Boundary Review

All management surfaces (enrollment grants, retirement, policy, trust,
anchor keys, identity/credential lifecycle, continuation resolution,
executions, exports) are operator-only by the default-deny gate.
Agent token → 403 verified on all tested endpoints (FR-E). No role-
field, method-change, or path-confusion bypass found — authorization
keys on `(method, path)` with the agent list exhaustive, not pattern-
permissive.

**Result: PROVEN.**

## 21. Findings

### F-01
- **Severity:** MEDIUM
- **Title:** Receipt persistence failure silently discarded; false `receipt_issued` event emitted
- **Affected Component:** `runtime/gateway/internal/handlers/runtime.go` `recordDecision` (lines ~1549–1591)
- **Attack Preconditions:** receipts store write failure (disk full, permission loss, filesystem error). Not remotely triggerable by the agent; requires environmental failure or trust-domain access.
- **Attack:** cause `receiptsStore.Put` to fail; the decision still returns, `receipt_issued` event still fires.
- **Expected:** I3 — every transit produces evidence; events must not assert what did not happen.
- **Observed:** `_ = h.receiptsStore.Put(receipt)` discards the error; the `receipt_issued` event fires inside the same block regardless — the event log can claim a receipt that was never persisted, which is worse than a gap because an auditor stops looking.
- **Security Impact:** evidence-completeness hole + misleading audit trail under store failure. Authorization unaffected (the decision is already made; execution is unaffected).
- **Reproduction:** make the receipts path unwritable, submit a request, observe `receipt_issued` in the event log and no record in the receipts store.
- **Root Cause:** single `if` block couples Put + events; Put error unchecked.
- **Existing Test Coverage:** none for Put failure.
- **Recommended Remediation:** check the Put error; on failure emit `receipt_persist_failed` (not `receipt_issued`); optionally gate on a config choice whether evidence failure is transit-fatal.
- **Invalidates existing claim?:** partially — I3 is already documented IMPLEMENTED-not-fully-tested; this is the concrete hole.
- **Status:** documented; not auto-fixed per review rules.

### F-02
- **Severity:** LOW
- **Title:** Referenced boundary tests absent from the tree
- **Affected Component:** `docs/OVARA_2_SECURITY_INVARIANTS.md` I1 references `tests/boundary/netns_test.sh`, `tests/boundary/docker_test.sh`
- **Attack Preconditions:** n/a (documentation/test gap)
- **Attack:** n/a
- **Expected:** referenced verification assets exist and are runnable.
- **Observed:** `tests/boundary/` does not exist; I1's "LIVE VERIFIED" rests on manual runs not reproducible from the repo.
- **Security Impact:** the only non-software-bounded invariant loses reproducible evidence.
- **Reproduction:** `ls tests/boundary` → no such directory.
- **Root Cause:** test assets never committed.
- **Existing Test Coverage:** none.
- **Recommended Remediation:** commit the two scripts or amend the doc to state manual-only verification.
- **Invalidates existing claim?:** no — I1 is documented as deployment-bounded and manually verified.
- **Status:** documented.

### F-03
- **Severity:** LOW (hardening; preconditioned on trust-domain write access)
- **Title:** Execution-queue persistence lacks integrity protection; planted continuation executes after restart
- **Affected Component:** `runtime/gateway/internal/execution` / continuation JSONL store
- **Attack Preconditions:** write access to gateway state files (assumption A6 excludes this for the agent; a trust-domain writer is operator-equivalent — but "operator-equivalent" includes backup scripts, co-located services, misconfigured mounts).
- **Attack:** append a fabricated `state:"queued"` continuation with a `shell:` resource; restart the gateway; the record is claimed and executed.
- **Expected:** under the documented model, persistence is authoritative — behavior is consistent. As hardening, tamper should be *detected* like trust-journal tamper.
- **Observed:** planted record → `executing → executed`; tampered `resource` executed as recorded. Revoked-lease planted records were still denied at claim (FR-C) — the revocation revalidation is the only integrity backstop and it only covers captured authority IDs, not action/resource.
- **Security Impact:** a trust-domain writer gains silent execution authority; trust journals detect the same class of tamper, the execution queue does not.
- **Reproduction:** `final_review.py` FR-A/FR-K — appended line + restart → executor ran.
- **Root Cause:** continuation store is plaintext append JSONL; no hash chain, no HMAC, no signature binding record→decision.
- **Existing Test Coverage:** p234 covers claim-time authority; nothing covers record integrity.
- **Recommended Remediation:** reuse the existing hash-chain journal format for continuations, or HMAC each record with the gateway key; either converts silent tamper into startup refuse.
- **Invalidates existing claim?:** no — explicitly inside the documented trust-domain assumption.
- **Status:** documented; architectural limitation + hardening recommendation.

### F-04
- **Severity:** INFORMATIONAL
- **Title:** Escalated-decision provenance is in-memory only; restart loses in-flight escalations
- **Affected Component:** `decisionCache` (runtime.go) / approval provenance
- **Observed:** approval create after restart → 404 "unknown decision_id". Fail-closed (no fabrication possible), availability-only impact.
- **Invalidates existing claim?:** no.
- **Status:** documented.

### F-05
- **Severity:** INFORMATIONAL
- **Title:** Credential revocation does not freeze queued continuations
- **Observed:** FR-D2 — queued continuation executed after its credential was revoked; new auth under the credential → 401. Documented semantic: claim-time revalidation covers lease/delegation/issuer; identity suspension is the freeze control.
- **Risk:** semantic over-reading — "revoked the credential" does not mean "stopped the work".
- **Recommended Remediation:** none required; keep docs explicit (they are).
- **Status:** documented.

## 22. Security Claim Matrix

| ID | Claim | Enforcement | Tests | Adversarial | Result |
|----|-------|-------------|-------|-------------|--------|
| I1 | Mandatory egress | nftables netns/docker boundary script | referenced tests absent; manual verified | not reproducible from repo | ARCHITECTURAL LIMITATION |
| I2 | Credential custody | proxy custody-by-construction + response scrubber | rc1 46/46 | reflector echo → [REDACTED] | VERIFIED |
| I3 | Complete evidence | recordDecision + execution journal | partial | Put-failure → silent gap + false event (F-01) | PARTIALLY PROVEN |
| I4 | Denied cannot execute | atomic resolve; non-claimable states | rc1/p22-gate | planted denied record → never claims | VERIFIED |
| I5 | Approvals single-use + bound | server-side rebuild; RequestHash+PolicyVersion bound; idempotent-per-decision | p22-gate | divergence rejected; replayed approve idempotent | VERIFIED (doc status stale) |
| I6 | Policy agent-immutable | EvalSymlinks confinement; operator-only API | rc1 | agent → 403 all policy routes | VERIFIED |
| I7 | Evidence agent-immutable | host placement + hash chain | p233 | mid-chain tamper → startup refuse | VERIFIED (anchor deletion-detect partial, documented) |
| I8 | Bypass attempts observable | security events on fabricate/tamper/replay | partial | API-layer events verified; fs-level monitor not built | PARTIALLY PROVEN (documented) |
| I9 | Honest coverage | process invariant | n/a | n/a | NOT CLAIMED as testable |
| I10 | Fail-closed | deny-all no-token; corrupt-store refuse; unknown-mode refuse | rc1 + FR-G | verified | VERIFIED |
| C-1 | Caller cannot choose principal | credential→ctx principal | p22 | forged subject_id/identity fields → overwritten | PROVEN |
| C-2 | Revoked/expired/suspended credential fails closed | idregistry.Authenticate | p22 + FR-D | revoked → 401 | PROVEN |
| C-3 | Delegation integrity (sig/issuer/narrow/audience/nonce) | evaluator ordered validation | p234 44/44 | all mutations rejected; canon probes fail closed | PROVEN |
| C-4 | Lease revocation enforced at claim | RevocationPairs→CheckClaimAuthority | p234 + FR-C | revoked lease on planted record → denied | PROVEN |
| C-5 | Credential revoke freezes queued work | — (not a claim) | — | executes post-revoke (documented) | NOT CLAIMED / ARCHITECTURAL LIMITATION |
| C-6 | Claim atomicity | persisted transition | FR-A/K | no double-claim; planted state honored per model | VERIFIED (bounded) |
| C-7 | Persistence authoritative + tamper-evident | hash-chain trust journals; plaintext exec queue | FR-G | registry tamper detected; queue tamper silent (F-03) | PARTIALLY PROVEN |
| C-8 | Anchor rollback/equivocation detect | reconcileAnchor frozen table | p233 65/65 | L<A refuse; diff-tip refuse; L>A no auto-push | VERIFIED (single-oracle scope) |
| C-9 | No cross-domain trust | audience binding; (gw,key) registry; anchor pin | p233/p234 + FR | foreign artifacts rejected | PROVEN |
| C-10 | Receipt binds all fields; historical verify | edsigner + registry resolver | p235 43/43 | any field tamper → invalid | PROVEN |
| C-11 | Agent cannot reach operator routes | default-deny agentAllowlist | FR-E | 403 on all 8 tested surfaces | PROVEN |
| C-12 | Durable replay protection | replay.FileStore | p21 7/7 + FR-J | rejected while journal exists; deleted journal → reuse (documented) | VERIFIED |
| C-13 | No credential reflection/exposure | scrubber; no secret logging; whoami scope | rc1 | swept | VERIFIED |

## 23. Residual Limitations

1. **Egress boundary is deployment-enforced.** OVARA provides the
   boundary script and the policy point; nothing in the software
   prevents an agent on an unbounded network from egressing directly.
   The docs state this correctly; adopters must deploy the netns/docker
   boundary and re-verify on topology change.
2. **Software keys, not hardware roots.** D-08: cloning is *detected*
   via duplicate-ID conflict, not prevented; full filesystem cloning
   inherits registry+key+anchor state.
3. **Local trust domain.** Shared-state trust domain (D-15); oracle
   replication unimplemented (D-13). Joint registry+oracle rollback is
   the documented trust-root compromise case.
4. **Execution-queue persistence not tamper-evident** (F-03): inside
   the trust-domain assumption, but asymmetric with trust journals.
5. **Credential revocation ≠ queued-work freeze** (F-05): identity
   suspension is the freeze; semantic documented but easy to over-read.
6. **Receipt validity ≠ execution truth/completeness/immutability** —
   documented non-claims, confirmed accurate.
7. **Evidence completeness has a store-failure hole** (F-01) — the
   false `receipt_issued` event is the sharp edge.
8. **Escalations don't survive restart** (F-04) — fail-closed,
   availability-only.
9. **Local journal ≠ externally immutable history** — replay-journal
   deletion resurrects nonces (documented).
10. **Host executors run on the gateway host** — `shell:` is `sh -c`;
    correct under the model, but the executor surface *is* the blast
    radius; prefer `shell.sandboxed` where available.

## 24. Regression Results

| Suite | Result |
|-------|--------|
| `go vet ./...` (gateway) | clean |
| `go test ./...` (gateway) | 33 packages ok, exit 0 |
| `go test -race ./...` (gateway) | 33 ok, exit 0 |
| proxy + 11 sibling modules | all ok |
| rc1_harness | 46/46 |
| p21_harness | 7/7 |
| p22_harness | 21/21 |
| p22_gate_harness | 37/37 |
| p231_harness | 22/22 |
| p232_harness | 35/35 |
| p233_harness | 65/65 |
| p234_harness | 44/44 |
| p235_harness | 43/43 |
| p236_harness | 56/56 |
| final_review.py (new adversarial) | 28/29 — the miss was a harness parse artifact; journal confirmed documented behavior (FR-D2) |
| canonicalization probe | 18/18 fail-closed or correct |

**Frozen checks total: 376/376. Independent adversarial checks: 47**
(29 e2e + 18 canonicalization). No genuine regressions; no failures
hidden.

## 25. Final Security Status

**FINAL SECURITY REVIEW — PASS WITH DOCUMENTED LIMITATIONS**

Rationale: every tested authorization property holds — no CRITICAL or
HIGH bypass found; no executor path escapes the claim→authority
boundary; authentication, delegation, lease, approval, claim, anchor,
receipt, cross-domain, and operator-separation claims verified against
code and adversarially reproduced. Meaningful residual limitations
remain (deployment-bounded egress, trust-domain persistence integrity,
evidence-store failure semantics, software-key identity), all of which
are documented in the product's own threat model — none invalidate a
claim as documented. I3 stands at PARTIALLY PROVEN pending F-01
remediation; I1 stands as ARCHITECTURAL LIMITATION by design.

Verified under the tested threat model. Bounded by assumption A6
(trust-domain filesystem). Not a blanket "secure" claim.

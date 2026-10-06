# TASKS — prioritized queue

Owner roles: builder / red-team / verifier / writer. Status: todo / doing /
done / blocked(reason).

## Phase 0 (exit needs: v1 audit, v1 bypass report, prior-art table, go/no-go)

- [x] P0-01 builder — Workspace + state files on `feat/agent-control-program`.
  AC: files exist, committed, mirrors cloned. Evidence: git log.
- [x] P0-02 builder — `docs/v1_audit.md`: modules, 14 action types,
  interception, receipts, policy, sandbox, tests, deps, MAP/POLICY.md status.
  AC: every claim evidence-tagged; test results recorded. Evidence: file.
- [x] P0-03 builder — SDK test suites: `sdk/typescript` vitest, `sdk/python`
  pytest. AC: results in daily report; failures logged verbatim.
- [x] P0-04 builder — `ovara demo` + `ovara doctor` run on host; capture output.
  AC: demo output stored under workspace/state/logs/ or daily report.
- [ ] P0-05 verifier — Re-verify each BYPASSES.md "fixed?" row against current
  code (SEC-0005, SEC-0010, REC-A8, agent_token default in `ovara init`).
  AC: rows get corrected status + file:line evidence.
- [x] P0-06 writer — `research/prior_art.md`: capability security (object
  caps, macaroons, biscuits), SPIFFE/SPIRE, OPA/Rego, Cedar, SLSA/in-toto,
  Sigstore/Rekor, CT, IFC-for-LLM-agents, agent sandboxes/guardrails.
  AC: table with per-system columns (mechanism, what it binds, what it
  can't do, relevance to OVARA); novelty claims require the table first.
- [ ] P0-07 red-team — v1 bypass report (dynamic part BLOCKED on A1):
  static classification of brief §7.3.3 bypass classes against v1 code.
  AC: per class status (blocked/detected-only/undetected/static-suspect)
  with file evidence; dynamic claims explicitly deferred.
- [x] P0-08 builder — v1 behavioral corpus: recorded request/response pairs
  from the evaluator for differential testing (drive evaluator in-process
  on macOS — no sandbox needed). AC: corpus dir + README in research/.
- [x] P0-09 writer — go/no-go document for the rewrite: scope, rationale
  (audit §11 + bypass ledger), retained components list. AC: operator
  sign-off requested via HUMAN_ATTENTION.
- [ ] P0-10 builder — Sandbox lane decision: install colima/docker on this
  Mac (needs operator OK for cask install) OR pin sandboxed work to a
  future Linux session. Blocks all dynamic adversarial work. (A1)

## Phase 1 (done; spec set v0.9 + prereg committed)

- [x] P1-01 — spec/threat_model.md (P1-P13, TCB, assumptions; §7 added per
  external review: 4 control layers, control-independence, TCB-surface metric)
- [x] P1-02 — spec/: action_model, capability_token, policy_ir, decision
  semantics, audit_log, approval_protocol, revocation, selftest
- [x] P1-03 — docs/mechanism_study.md (netns+proxy, seccomp-notify, Landlock,
  docker→gVisor→Firecracker lanes; measured prototypes deferred to Linux)
- [x] P1-04 — research/preregistration.md H1-H8 (+H9-H12 from external review)

## Phase 2 — redesign inside OVARA (branch feat/ovara-redesign)

- [x] core/audit — write-ahead chain + signed Merkle checkpoints + off-host sink
- [x] core/action — closed 26-type vocab; host-boundary canonical net form;
  userinfo rejected; parse-based shell canonicalization
- [x] core/capability — stdlib-Ed25519 attenuable tokens (subset, epoch, expiry)
- [x] core/policy — total-order eval + shadow analysis + naive ref interpreter
- [x] core/decide — signed-request pipeline (freshness→epoch→replay→sig→cap→policy)
- [x] core/selftest — 8 checks w/ expected-failure negatives; boot refuses on fail
- [x] HTTP surface — POST /v2/runtime/check (agent-scope), write-ahead audit
  before response; core_enabled/core_* config fails closed at startup
- [x] P2-08 differential — v1 corpus 45/45 vs annotated core outcomes
  (runtime/gateway/tests/differential; found+fixed host-* suffix leak)
- [x] P2-fold — proxy signs requests to /v2 when request_key_file set
  (verified live: allow forwarded, deny blocked, decisions audited)
- [ ] P2-05 sandbox layer (netns/seccomp/Landlock) — BLOCKED on Linux lane
- [x] P2-09 red-team gate — 8 attack classes, all denied; 3 real holes
  found+fixed (canonical trust, IP-spelling, host-* leak)
- [x] fuzz targets — 3 targets ~140M execs clean; 6 canonicalizer bugs
  found+fixed; bench 45µs/decision (virtualized M4)
- [x] migration/compat doc → workspace/docs/migration.md
- [x] RT-R1 durable replay — ReplayStore JSONL + core_replay_file
- [x] RT-R2 env binding — env_in caveat enforced; unenforced caveats
  fail closed
- [ ] performance measurement on real Linux (deferred with P2-05)

## Standing

- [ ] STOP check before each task burst; every ~15 min on long tasks.
- [ ] Log every action to state/logs/actions.jsonl.
- [ ] Daily report at session end → state/daily/YYYY-MM-DD.md.
- [ ] Adversarial pass on anything touching a security property.

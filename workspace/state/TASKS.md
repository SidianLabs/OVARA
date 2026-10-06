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
- [ ] P0-06 writer — `research/prior_art.md`: capability security (object
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
- [ ] P0-09 writer — go/no-go document for the rewrite: scope, rationale
  (audit §11 + bypass ledger), retained components list. AC: operator
  sign-off requested via HUMAN_ATTENTION.
- [ ] P0-10 builder — Sandbox lane decision: install colima/docker on this
  Mac (needs operator OK for cask install) OR pin sandboxed work to a
  future Linux session. Blocks all dynamic adversarial work. (A1)

## Phase 1 (not started; exits on spec set v0.9 + prereg)

- [ ] P1-01 — Formal threat model doc (P1-P13 formalized, TCB enumeration,
  assumptions list) → spec/threat_model.md
- [ ] P1-02 — Specs: action model + canonicalization; capability token
  format; policy IR + POLICY.md compiler semantics; decision record;
  audit log format; approval + revocation protocols; self-test design.
- [ ] P1-03 — Interception mechanism study w/ measured prototypes
  (needs A1 resolved for Linux mechanisms).
- [ ] P1-04 — Pre-register hypotheses + scenario schema → research/prereg/.

## Standing

- [ ] STOP check before each task burst; every ~15 min on long tasks.
- [ ] Log every action to state/logs/actions.jsonl.
- [ ] Daily report at session end → state/daily/YYYY-MM-DD.md.
- [ ] Adversarial pass on anything touching a security property.

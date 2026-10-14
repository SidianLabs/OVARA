# The Ovara sandbox contracts — specification 0.1

This directory is the written form of what the reference implementation
(this repository) does at the points where another implementation, or a
tool that embeds this one, has to agree with it. Nothing here is a plan: a
statement that is not true of the code is a bug in one or the other, and
tests in the modules keep the two from drifting (`spec_schema_test.go` next
to each type the schemas describe).

| Contract | Document | Schema | Fixed by |
|---|---|---|---|
| C1 Resource model: how an action is written down so two implementations decide the same thing | [`resource-model.md`](resource-model.md) | (in C3's request) | `runtime/gateway/internal/policy` (`CanonicalResource`, `SplitRefList`), `proxy/internal/boxgate` (`PolicyLine`), the proxy's gates |
| C2 Policy: the document, matching, precedence | [`policy.md`](policy.md) | [`schemas/policy.schema.json`](schemas/policy.schema.json) | `runtime/gateway/internal/policy`, `internal/evaluator` |
| C3 Decision API: check, approvals, claim, roles | [`decision-api.md`](decision-api.md) | [`schemas/decision-request.schema.json`](schemas/decision-request.schema.json), [`schemas/decision-response.schema.json`](schemas/decision-response.schema.json) | `runtime/gateway/internal/handlers`, `internal/auth`, `internal/approval` |
| C4 Evidence: the receipt chain, its signing form, keys, anchors | [`evidence.md`](evidence.md) | [`schemas/receipt-v2.schema.json`](schemas/receipt-v2.schema.json) | `proxy/internal/receipts`; vectors in `sdk/testdata/receipts_v2.json` |

A fifth contract, the sandbox runtime interface (create a sandbox from a
manifest, start the agent, stream events, finish), is not in 0.1: `ovara
box` does it as a command, and the programmatic form is being extracted from
it.

## Status and versioning

- **0.1** describes the code on the `main` branch at the commit that
  carries this directory. While the version is 0.x the contracts may change
  with the code; every change is recorded in `CHANGELOG.md` under "Spec".
- **1.0** will be declared only when an independent security review has
  reported no open Critical or High finding (`docs/REVIEW_SCOPE.md`) and a
  second implementation passes the conformance suites below. From 1.0 the
  `/v1` decision API never breaks: fields are added as optional, never
  removed or changed in meaning; a change that needs more goes to `/v2`.
- The promises the implementation makes, and the tests behind each, are in
  [`docs/GUARANTEES.md`](../docs/GUARANTEES.md). This directory is the
  interface; that file is the behaviour.

## Conformance

An implementation conforms to a contract when it passes the tests that fix
it. They are ordinary Go tests and shell suites in this repository, listed
per contract in each document's last section; the agents matrix, the
boundary red team and the separate-user attacks (`tests/`) are the
end-to-end part. A packaged runner that points them at another
implementation is planned; until then, conformance means running them.

## Changing a contract

Open a pull request that changes the code, the document and the schema
together. The drift tests will not let a field into the code without its
schema, or into a schema without the code.

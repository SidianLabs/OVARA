# Ovara conformance suite

A second implementation of the Ovara contracts (`spec/`) is conformant when
it makes the same decisions the reference implementation makes. This folder
packages that check: machine-readable **vectors** an implementation can run
against itself, plus pointers to the live-deployment suites for the parts
that need a running sandbox.

The vectors are **generated from the reference implementation**, never written
by hand, and a CI test fails if the reference ever drifts from them (so the
published vectors always describe real behaviour). Regenerate with:

```
OVARA_WRITE_CONFORMANCE=1 go test ./runtime/gateway/internal/policy  -run TestConformanceVectors
OVARA_WRITE_CONFORMANCE=1 go test ./runtime/gateway/internal/evaluator -run TestConformancePrecedence
```

## What each contract's conformance means

| Contract | Spec | How to check it |
|---|---|---|
| **C1 Resource model** | [`spec/resource-model.md`](../spec/resource-model.md) | `vectors/canonical.json`, `vectors/match.json` |
| **C2 Policy** | [`spec/policy.md`](../spec/policy.md) | `vectors/match.json`, `vectors/specificity.json`, `vectors/precedence.json` |
| **C3 Decision API** | [`spec/decision-api.md`](../spec/decision-api.md) | the request/response JSON Schemas in [`spec/schemas/`](../spec/schemas); drive your `/v1/runtime/check` with the C2 precedence vectors |
| **C4 Evidence** | [`spec/evidence.md`](../spec/evidence.md) | [`sdk/testdata/receipts_v2.json`](../sdk/testdata/receipts_v2.json) — verify each `line` against `public_key`; `valid` is the expected result |
| **C5 Sandbox runtime** | [`spec/runtime.md`](../spec/runtime.md) | the manifest/event schemas in [`spec/schemas/`](../spec/schemas); the live suites below |

## The vectors

### `vectors/canonical.json` (C1)
Each entry is an `input` and its `canonical` form, or `canonical: null` when
the input is **not canonical** (it then matches no URL-shaped rule). An
implementation's canonicaliser must produce the same string, and reject the
same inputs (userinfo, `.`/`..` path segments, a bare host with no method and
path, an unparseable URL). See `spec/resource-model.md` §2.

### `vectors/match.json` (C1 + C2)
Each entry is a rule `pattern`, a request `resource`, and whether they
`match`. This is the core cross-implementation function: decide the same way
about whether a rule applies to a destination. The corpus is the red-team
matrix — host-boundary bypasses (suffix/prefix/look-alike hosts, userinfo,
IP literals), method and git-ref smuggling, and encoded dot segments — so an
implementation that passes it resists the same attacks.

### `vectors/specificity.json` (C2)
Each entry is a `pattern` and its integer `specificity`, the key used by the
`most-specific` precedence mode (higher wins). An implementation must rank
patterns the same way or it will pick a different winner.

### `vectors/precedence.json` (C2)
Each entry is a `policy` document, a request (`action_type`, `environment`,
`resource`), the resulting `decision` (`allow` / `deny` / `escalate`) and the
`matched_rule`. It exercises both precedence modes (`order`: any matching
deny wins, else the first match; `most-specific`: highest specificity wins,
deny breaks ties) and the `default` when nothing matches.

### `sdk/testdata/receipts_v2.json` (C4)
Receipt test vectors already consumed by the Go, Python and TypeScript
verifiers (`sdk/*/...`). Each vector carries a receipt `line`, whether it is
`valid`, and the `public_key` to verify it under. A conformant evidence
implementation reaches the same verdict for every vector, including the
tamper cases.

## The live suites (C3, C5, and enforcement)

Some conformance can only be shown against a running sandbox. These live in
[`tests/`](../tests) and are run the way the reference runs them in CI:

- **Agents matrix** (`tests/agents/`): real agents behind the sandbox make the
  same requests and get the same allow/pause/block outcomes.
- **Boundary red team** (`tests/redteam/boundary/`): attempts to leave the
  box by a path other than the proxy, in netns, docker and tier 2 modes.
- **Separate-user attacks** (`tests/redteam/separate-user/`): a second user on
  the host cannot read Ovara's keys or rewrite its logs.

An implementation claiming "enforced" must pass these in its own environment;
they are not reducible to static vectors.

## Status

0.x, tracking the contracts while the external review is open (`spec/README.md`
and `docs/REVIEW_SCOPE.md`). The vector sets grow as the contracts do; a new
corpus entry is a new line in the generators and a regenerated file.

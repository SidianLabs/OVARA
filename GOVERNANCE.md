# Governance

Ovara is two things with different stability needs, and this document keeps
them apart:

- **The contracts** (`spec/`): the five interfaces — resource model, policy,
  decision API, evidence, sandbox runtime — that another implementation must
  meet. These change slowly and under the process below.
- **The implementation** (everything else): the reference code. It changes
  like any codebase, by pull request, and its behaviour is pinned by the
  tests in `docs/GUARANTEES.md`.

While the project is pre-1.0 the two move together; the separation matters
most at 1.0, when the contracts are meant to be something others build on.

## Who decides

- **Maintainers** review and merge pull requests to the implementation, and
  cut releases. Today the maintainer is SidianLabs.
- **A steering group** owns the contracts: it approves RFCs (below), the
  compatibility promise, and the deprecation policy. The intent for 1.0 is a
  small group with **at least one member from outside the company**, so the
  contracts are not governed by a single vendor. Until that group is seated,
  contract changes still follow the RFC process and are recorded in the open;
  this file names the group's members once they are.

Decisions are made in the open: an issue or pull request, a visible
discussion, and a recorded outcome. Lazy consensus (no sustained objection
within a stated review window) is enough for the implementation; a contract
change needs an explicit approval.

## Changing a contract: the RFC process

A change to anything in `spec/` — a new field, a new action type, a change in
how a resource is written or a decision is reached — goes through an RFC so
that implementers see it coming and can object before it ships. The process
and the template live in [`spec/rfcs/`](spec/rfcs/README.md). In short:

1. Open an RFC from the template describing the change, why, and its effect on
   existing implementations.
2. Discuss it in the open for the review window (two weeks for a breaking
   change, shorter for an additive one).
3. On approval, land it as one pull request that changes the **document, the
   JSON Schema, the code and the conformance vectors together** — the drift
   tests (`spec_schema_test.go`, the conformance generators) refuse a change
   that touches only some of them.
4. Record it in `CHANGELOG.md` under "Spec".

A pure implementation change (a bug fix, a new test, a refactor that keeps the
contracts) does not need an RFC — just a pull request.

## The compatibility promise

- **Before 1.0 (`0.x`):** the contracts may change with the code. Every change
  is in `CHANGELOG.md` under "Spec", and the version in `spec/README.md` says
  what the schemas describe.
- **From 1.0:** the `/v1` decision API never breaks. Fields are **added only
  as optional**; a field is never removed, renamed, or changed in meaning
  within `/v1`. A change that cannot be made that way goes to `/v2`, and `/v1`
  keeps working alongside it. The policy and receipt schemas follow the same
  rule: a document valid under one 1.x release stays valid under every later
  1.x release, and a receipt written by one 1.x release verifies under every
  later one.
- **Across the implementation:** every 1.x release reads every earlier 1.x
  deployment; the upgrade is tested against the previous minor release
  (`tests/scenarios/run.sh upgrade`).

## Deprecation policy

Nothing in a shipped contract is removed without notice.

1. **Announce.** A field or behaviour marked deprecated is called out in
   `CHANGELOG.md` and in the relevant `spec/` document, with what replaces it.
2. **Keep it working.** A deprecated part of `/v1` keeps working for the rest
   of `/v1` — it is never removed inside the same major version.
3. **Remove only at a major bump.** Removal happens at `/v2`, with `/v1` still
   served for a stated overlap window so implementations have time to move.
4. **Security is the one exception.** If keeping a behaviour is itself the
   vulnerability, it is handled through `SECURITY.md` and
   `docs/SECURITY_RELEASE.md`, with an advisory, rather than waiting for a
   major bump. Such a change is called out as security-driven.

## Security and disclosure

Vulnerability reports and the disclosure timeline are in
[`SECURITY.md`](SECURITY.md). The external review that gates 1.0 is scoped in
[`docs/REVIEW_SCOPE.md`](docs/REVIEW_SCOPE.md); its report is published before
the words "sandbox" and "enforced" are used without qualification.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

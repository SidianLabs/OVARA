# Contract RFCs

A change to a contract in `spec/` goes through an RFC so implementers see it
before it ships. See [`GOVERNANCE.md`](../../GOVERNANCE.md) for who approves
and the compatibility rules an RFC must respect.

## When an RFC is needed

- A new or changed **action type** or **resource form** (C1).
- A change to **policy** matching, precedence, or the policy document (C2).
- A change to the **decision API** request or response (C3).
- A change to the **evidence** format — receipts or attestations (C4).
- A change to the **sandbox runtime** manifest, events, or summary (C5).

A bug fix, a test, or a refactor that keeps every contract does **not** need an
RFC. If you are unsure whether a change touches a contract, the drift tests
decide for you: if `spec_schema_test.go` or a conformance generator fails, you
changed a contract.

## How

1. Copy [`0000-template.md`](0000-template.md) to
   `NNNN-short-title.md` (next free number) and fill it in.
2. Open it as a pull request. Discuss in the open for the review window: two
   weeks for a change that is not backward compatible, shorter for a purely
   additive one.
3. On approval, land the change as **one** pull request that updates the
   document, the JSON Schema, the reference code, and the conformance vectors
   together. The drift tests refuse a partial change.
4. Add a `CHANGELOG.md` entry under "Spec".

Before 1.0 the review window can be short and the bar is "is this the right
shape"; after 1.0 an RFC must also show it keeps the compatibility promise, or
be scoped to the next major version.

## Index

| RFC | Title | Status |
|-----|-------|--------|
| 0000 | Template | — |

# RFC NNNN: <short title>

- **Contract(s):** C1 resource model / C2 policy / C3 decision API / C4 evidence / C5 sandbox runtime (list the ones this touches)
- **Status:** draft / in review / accepted / rejected / superseded
- **Author(s):**
- **Opened:** YYYY-MM-DD
- **Review window closes:** YYYY-MM-DD

## Summary

One paragraph: what changes, in plain terms.

## Motivation

What does this make possible, or fix, that the current contract does not?
Point to the real need (a request pattern, an agent, an attack) rather than a
hypothetical.

## Design

The change itself, precisely enough to implement: the exact field, resource
form, decision rule, schema edit, or event. Show before/after where it helps.

## Compatibility

- Is this **additive** (a new optional field / action type / event), or does it
  change or remove something?
- What does an existing implementation that does not know this change do when
  it sees it? What does a new implementation do against an old peer?
- If it is not backward compatible under the compatibility promise
  (`GOVERNANCE.md`), it targets the next major version — say so.

## Conformance

What vectors or test cases prove an implementation got this right? A change
without a way to check it is not done.

## Alternatives considered

What else was weighed, and why this.

## Unresolved questions

Anything still open at the time of review.

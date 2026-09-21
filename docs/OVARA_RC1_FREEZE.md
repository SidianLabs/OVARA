# OVARA 2.0 — RC1 FREEZE MARKER

**RC1 STATUS = FROZEN**

| Field | Value |
|---|---|
| CONTENT ID | `17649ac6fc36a25a0a2ec297f2e4ebeef8008bb5` |
| BASE COMMIT | `7fc1b685463efc7828a34c5a1ff697c2a4040aa2` |
| Branch | `security-freeze/rc1` |
| Freeze commit | None — no git identity configured; content pinned by write-tree hash above (computed over the full tree excluding `docs/OVARA_RC1_SECURITY_REPORT.md` and this freeze marker; reproducible via `git add -A && git reset docs/OVARA_RC1_SECURITY_REPORT.md docs/OVARA_RC1_FREEZE.md && git write-tree`) |

## Recorded verification state

- **46/46** clean-room E2E cases pass (`tests/e2e/rc1_harness.py`,
  fresh CA / issuer keys / credentials / state / policy / receipts /
  nonces per run)
- **race clean** — `go test -race ./...` on all gateway internal and
  proxy packages
- **R1 fixed** — `%2e%2e` encoded dot-segment traversal rejected
  fail-closed at the shared canonicalizer
- **R2 fixed** — proxy derives its credential-bound principal
  (`ag_<sha256(token)[:16]>`); positive + negative regression coverage;
  `bindIdentity` not weakened
- **R3 fixed** — injected credentials scrubbed from response trailers
  as well as headers and body
- **No HIGH/CRITICAL findings remain** in the RC1 review
- All security claims are scoped to the tested environment and the
  single-tenant threat model in `docs/OVARA_2_THREAT_MODEL.md`

## Explicit non-claims (do not inflate)

- Durable replay protection is **not** claimed — delegation replay
  state is process-local, in-memory, 5-minute TTL
- External receipt immutability is **not** claimed — receipts are
  tamper-evident within the implemented trust boundary only
- Credential lifecycle — **DEFERRED**
- Persistent identity — **DEFERRED**
- Runtime revocation — **DEFERRED**
- Final network containment verification — **DEFERRED**

## Freeze rules

No source changes, no refactors of the security boundary, no new
features, no security-semantics changes on this baseline. A change to
this tree invalidates the content ID above and requires re-running the
full RC1 verification.

## Milestone boundary

**Next milestone: OVARA 2.0 — P2 TRUST & LIFECYCLE** (not started).

P2 covers: credential lifecycle · persistent identity · durable
delegation replay protection · runtime delegation revocation ·
receipt anchoring · final network containment verification ·
integrity monitoring (I8).

P2 begins with THREAT MODEL and DESIGN SPEC only. No implementation
until the P2 architecture is reviewed against the RC1 guarantees —
RC1 is the baseline P2 must not weaken.

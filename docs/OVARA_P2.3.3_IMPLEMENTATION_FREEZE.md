# OVARA 2.0 — P2.3.3 Implementation Freeze
## Locked implementation architecture — the coding phase may not reinterpret these decisions

Status: FROZEN for implementation. Design doc:
`OVARA_P2.3.3_ROLLBACK_ANCHORING_DESIGN.md` (amended). This document
locks the implementable form of every decision. No code yet.

## 0. SetExpectedAudience — resolved

`SetExpectedAudience` binds lease/delegation validation to the
enrollment `gw_id` (name-match, `validator.go`). It is NOT in HEAD —
the entire audience-binding feature (validator field/method, redteam
test, server.go call) is one uncommitted unit introduced by the
pre-P2.3 security-hardening line (documented as "current mechanism —
name-match" in `OVARA_P2.3_THREAT_MODEL.md` §1). It touches no
`gwidentity` machinery and P2.3.3 does not depend on it.

Classification: **unrelated/pre-existing hardening** — belongs to a
separate hardening freeze commit, not to P2.3 integration, not to
P2.3.3. No implementation dependency.

## 1. Oracle placement — locked

One protocol, two transports, one security model:

```
        gateway ── AnchorClient ──► oracle daemon
              unix socket (Tier 1)      or      HTTPS+mTLS (Tier 2)
```

- **Oracle = new standalone binary `ovara-anchor`** — same code in both
  tiers; deployment decides the boundary, the code doesn't.
- **Tier 1**: oracle listens on a unix socket `0700`-parented in its
  own uid's directory. Channel authentication = filesystem socket
  ownership. Oracle "identity" = socket path + expected-uid stat check
  (the pin's Tier-1 form).
- **Tier 2**: same HTTP API over TLS; oracle identity = pinned Ed25519
  pubkey (served as TLS key or signed handshake proof).
- Gateway holds ONE client implementation with two dialers. The
  security semantics — pin check, checkpoint verify, compare-and-store
  — are identical either way. No forked security model.

## 2. Oracle interface — locked

```go
// internal/anchor — the ONLY abstraction the gateway knows.
type Anchor interface {
    // Latest returns the oracle-stored checkpoint for domain, or
    // ErrDomainUnregistered.
    Latest(ctx context.Context, domainID string) (*Checkpoint, error)
    // Commit requests the oracle store cp for domain. Semantics §5.
    Commit(ctx context.Context, domainID string, cp *Checkpoint) error
}
```

Request authentication: Tier-1 = socket ownership (implicit);
Tier-2 = mutual TLS where the gateway authenticates with its
PoP-capable key. Checkpoint content authentication is ALWAYS the
Ed25519 signature — channel auth never substitutes for it.

Error vocabulary (gateway-visible, each maps to §10 semantics):
`ErrUnreachable`, `ErrTimeout`, `ErrMalformed`, `ErrOracleIdentity`
(pin mismatch), `ErrDomainUnregistered`, `ErrRegression`,
`ErrEquivocation`, `ErrBadSignature`, `ErrDomainMismatch`.

## 3. Authority model — four concepts, never merged

| Concept | Role | Implementation boundary |
|---|---|---|
| **Signature** | proves the checkpoint was authorized by the domain's registered signing principal | `anchor.Verify(cp, lineage)` |
| **Oracle store** | enforces monotonic sequence | oracle-side only — `store.Commit` |
| **Local hash chain** | detects local journal modification/reordering | `gwidentity` record `chain` field, fold-time verify |
| **Oracle pin** | authenticates the intended oracle | client dial-time check — separate from sig verify |

No single "security check" abstraction. A caller must pass four
distinct validations; collapsing any two is a review-reject.

## 4. Checkpoint format — locked (one canonical representation)

```
struct Checkpoint {
    version   : "v1"                      // literal, canonicalization-required
    domain_id : string                    // "dom_" + hex(sha256("OVARA-ANCHOR-DOMAIN-V1" || journal_line_1_bytes))
    seq       : uint64                    // journal record sequence
    tip_hash  : [32]byte                  // sha256 chain tip at seq
    key_id    : string                    // signing key record id
    sig       : [64]byte                  // Ed25519 over preimage
}

preimage = lp("OVARA-ANCHOR-CP-V1")
        || lp(domain_id)
        || lp(u64be(seq))
        || lp(tip_hash)          // raw 32 bytes
        || lp(key_id)
// lp(x) = u32be(len(x)) || x — the frozen PoP framing, reused.
```

On-wire: single JSON object `{version,domain_id,seq,tip_hash,key_id,sig}`
with hex-encoded byte fields; `seq` as a JSON number ≤ 2^53 — never a
string, never a float literal with exponent. Deterministic producer:
fields in this order; a verifier re-canonicalizes before verifying —
JSON field order on receipt is irrelevant because verification is over
`preimage`, not the wire bytes.

Test vectors (implementation phase, first deliverable): fixed key +
fixed checkpoint → fixed `preimage` bytes → fixed `sig`; a second
implementation producing different bytes fails the vector.

## 5. Oracle store semantics — locked (AM-6 durable)

Per-domain durable record `{seq, tip_hash, key_lineage}` in an
append-only JSONL store on the oracle's filesystem — same
flock+fsync+torn-tail pattern as `gwidentity` (reuse the pattern, not
the file). Update protocol inside one locked mutation:

```
current = N
PUT(seq = N, tip = T): if stored tip == T → idempotent OK
                       else → ErrEquivocation + ALERT
PUT(seq < N)         : ErrRegression
PUT(seq > N)         : verify signature+lineage+domain → append →
                       fsync → ack   (ack NEVER precedes fsync)
```

- Same-seq-different-content = **equivocation** — never accepted,
  always alerted.
- Persistence: restart → reload durable state; torn tail truncates to
  last complete record. In-memory state is forbidden as the sole copy.
- **No implicit domain initialization**: `Commit` on an unregistered
  domain → `ErrDomainUnregistered`. Registration happens ONLY via the
  explicit init ceremony (§8) — an oracle whose store was wiped does
  NOT re-anchor from whatever gateway connects first (PART 10).
- Oracle store backup/restore: restoring is an authority event —
  on boot the oracle logs last-checkpoint-per-domain loudly; an
  empty-after-restore store serves `ErrDomainUnregistered` (which
  gateways treat as fail-closed, not as a new bootstrap).

## 6. Domain isolation

Oracle state is keyed by `domain_id`. `Commit`/`Latest` reject when:
path domain ≠ body domain ≠ sig-covered domain. Cross-domain
checkpoints are inert (they'd fail lineage anyway — the sig verifies
under the domain's own key lineage). Domain substitution by the
gateway is impossible: the signature binds the domain, the lineage is
registered under it.

## 7. Oracle identity pin — locked

- **Config**: `gateway_anchor_pin` — hex Ed25519 pubkey (Tier-2) or
  `sock:<path>:uid:<n>` form (Tier-1). Stored in the gateway config
  file (operator-written, outside the registry — same convention as
  `trusted_issuers`).
- **Provisioning**: operator sets at domain provisioning from the
  oracle's out-of-band-published identity.
- **Rotation**: operator event; new pin out-of-band; mismatch after
  cutover fails closed loud.
- **Mismatch → FAIL CLOSED** in strict mode (dial refused).
- Strict mode with `anchor_mode=strict` and no pin → startup config
  validation fails.
- "Trust first responding oracle" exists ONLY inside the explicit
  bootstrap ceremony (`anchor-init`), never at runtime.

## 8. Migration — locked (`gwctl anchor-init`)

Two-step non-interactive ceremony:

```
gwctl anchor-init  --registry <path>            # step 1: inspect
gwctl anchor-init  --registry <path> --confirm  # step 2: commit
```

Step 1 prints the attestation artifact and writes NOTHING:
`{domain_id, journal tip seq, tip_hash, total records, per-gateway
active/retired keys, grant counts authorized/consumed/denied}`.
The operator verifies out-of-band; step 2 (re-run with `--confirm`)
assigns seq+chain in file order, appends `kind:"migrate"` marker,
emits genesis checkpoint, registers domain at oracle, and writes a
`kind:"anchor"` journal record naming the pushed seq.

Fail-closed cases: corrupt registry (refuse), conflicting records
(registry won't fold → refuse), ambiguous state (operator doesn't
confirm → nothing happens), already-registered domain (refuse —
that's the reset ceremony), pre-migration rollback (undetectable —
attestation legitimizes present state; the operator's confirmation is
the sole guard, stated limit).

Migration is an **attestation event, not a forensic one**.

## 9. Gateway rollback algorithm — locked

`initGatewayTrust`, after journal fold and before PoP self-check:

```
L = (local_tip_seq, local_tip_hash)      A = oracle.Latest(domain_id)

L <  A                       → REFUSE trust-init (rollback detected)
L == A && tip_hash equal     → ACCEPT
L == A && tip_hash differs   → REFUSE (corruption/forgery)
L >  A                       → strict: REFUSE pending operator
                               catch-up — NEVER auto-push (below)
A unreachable                → strict: REFUSE (§10)
A unregistered               → REFUSE (not a bootstrap path)
```

**Why L>A never auto-pushes**: a local tip newer than the oracle is
either a crash-window tail (legit) or a forged longer journal
(attacker with fs write — the gateway would sign and anchor it).
Auto-push converts rollback detection into authority escalation: the
attacker fabricates seq=very-high, the gateway anchors it, and every
honest history is permanently locked out. The correct distinction
cannot be made inside the trust model — so it goes to the operator.

**Operator catch-up** (`gwctl anchor-catchup --registry <path>`):
prints the unanchored tail records (seq range + kinds), requires
`--confirm`, then pushes the tip checkpoint. Strict default. A config
`anchor_catchup=auto` opt-in exists for availability-first deployments
— documented weaker (auto-push of unanchored tail), never default.

**Mutation-time semantics** (strict): `mutate()` = append → fsync →
`anchor.Commit(tip)` → ack → return. Push failure → caller sees error;
the committed record remains as unanchored tail — retried by the NEXT
mutation's tip-push (tip covers the whole tail, so forward progress
self-heals while running). Boot still requires reconcile per above.
The push happens inside the flock'd mutation so all writers on the
same journal push in commit order — no out-of-order oracle writes.

## 10. Failure semantics — locked matrix

| Condition | Strict behavior |
|---|---|
| oracle unreachable/timeout at mutation | mutation DENIED (record may be committed → unanchored tail, retried next mutation; boot reconcile still required) |
| oracle unreachable/timeout at boot | REFUSE trust-init |
| oracle malformed response | REFUSE (treat as unreachable + alert) |
| oracle signature/identity mismatch | REFUSE — pin violation, alert |
| oracle domain mismatch | REFUSE |
| oracle sequence rollback (returns older than W watermark) | REFUSE + ALERT (oracle regression signal; W is observability only) |
| oracle equivocation (same seq, diff hash) | REFUSE + ALERT |
| local journal corruption | REFUSE (existing fail-closed load) |
| local journal rollback (L < A) | REFUSE + operator reset ceremony |
| local ahead (L > A) | REFUSE + `anchor-catchup` (§9) |
| local behind with unreachable oracle | REFUSE (cannot distinguish) |
| already-authorized runtime ops (PoP, evaluation, adopt while running) | NEVER blocked by oracle state — read-only paths |

## 11. Co-rollback — locked claim

Implementation MUST NOT claim protection against joint restore of
registry + oracle to a mutually-consistent older state — that is
anchor/trusted-backup compromise, out of scope. Enforced by:
(a) oracle never implicitly re-initializes (§5), (b) oracle store on
an independent durability schedule (deployment requirement, §14
docs), (c) the watermark row in §10 alerts single-sided oracle
regression.

## 12. Tier security claims — preserved, never merged

- **Tier 1** (separate-uid local oracle): defeats registry-file,
  directory, and local-process attackers + accidents. Does NOT claim
  root/full-host.
- **Tier 2** (remote oracle): additionally defeats full local host
  compromise — assumes oracle trust root + network auth uncompromised.
- **TPM (optional tier)**: only local mechanism surviving root;
  orthogonal second anchor, never a substitute for the oracle's
  "latest" answer.

## 13. Test plan — locked (before code)

Unit (`internal/anchor`, `internal/gwidentity`):
- canonicalization vectors (fixed input → byte-identical preimage+sig)
- sig verify: valid/forged/wrong-key/wrong-domain
- domain substitution: A's checkpoint → B (reject)
- oracle identity substitution: wrong pin (dial refuse)
- oracle store: idempotent-PUT, seq< reject, same-seq-diff-hash
  equivocation, seq> accept+fsync ordering, restart durability,
  torn-write truncate
- journal chain: mid-file modify detect, reorder detect, seq gap math
- boot reconcile: every §9/§10 row
- migration: artifact determinism, confirm gating, all edge cases
- dual-sign rotation lineage at oracle
- race: concurrent mutations push in order; concurrent admit one-winner

Clean-room e2e (`tests/e2e/p233_harness.py`, real binaries incl. a
mock/reference oracle):
- restore-pre-consumption → refuse (was: replay)
- restore-pre-retirement → refuse (was: resurrect)
- truncate+restart → refuse
- kill between fsync and push → boot refuse → anchor-catchup → serve
- oracle outage: mutation refuse; boot refuse; running ops unaffected
- oracle wiped → ErrDomainUnregistered → refuse (no silent re-anchor)
- oracle backup restore → single-sided recover per matrix
- joint co-rollback → accepted-as-consistent, logged (documented
  residual, asserted as such — proves the boundary is where claimed)
- bootstrap race → single winner + alert
- key rotation across the anchor → lineage advances, old-key
  checkpoints still verify
- retirement + restore → tombstone survives
- degraded mode → bounded window documented, strict unaffected
- anchor off → byte-identical P2.3.2.1 behavior (regression floor)

## 14. Implementation boundary — files

**New files**
- `runtime/gateway/internal/anchor/checkpoint.go` — struct,
  canonicalization, sign/verify
- `runtime/gateway/internal/anchor/client.go` — `Anchor` interface,
  unix + TLS dialers, pin check
- `runtime/gateway/internal/anchor/store.go` — oracle-side durable
  compare-and-store (flock+fsync JSONL)
- `runtime/gateway/internal/anchor/*_test.go` — vectors + matrix tests
- `runtime/gateway/cmd/ovara-anchor/main.go` — oracle daemon
  (PUT/GET /v1/anchor/{domain})
- `runtime/gateway/internal/gwidentity/chain.go` — seq/chain record
  fields + fold-time verify
- `tests/e2e/p233_harness.py` — clean-room e2e
- docs: update `OVARA_P2.3.3_ROLLBACK_ANCHORING_DESIGN.md` claims to
  post-implementation status + new deployment guide section

**Modified files**
- `runtime/gateway/internal/gwidentity/store.go` — emit seq/chain on
  append; anchor hook inside `mutate()` (SetAnchor, push after fsync,
  inside flock); `kind:"anchor"` watermark + `kind:"migrate"` records
- `runtime/gateway/internal/config/config.go` — `gateway_anchor_url`,
  `gateway_anchor_pin`, `gateway_anchor_mode`,
  `gateway_anchor_domain` (optional explicit), `anchor_catchup`
- `runtime/gateway/pkg/server/server.go` — initGatewayTrust reconcile
  per §9; wire anchor into registry; strict/degraded/off modes
- `runtime/gateway/cmd/gwctl/main.go` — `anchor-init` (2-step),
  `anchor-status`, `anchor-catchup`, `anchor-reset`

**NOT changed**
- `internal/gwidentity/pop.go` — frozen PoP canonicalization (the
  checkpoint preimage reuses `lp()` but does not touch pop.go)
- `internal/idregistry`, `internal/replay`, evaluator, delegation
  canonicalization, proxy, enrollment — frozen paths
- `validator.go` SetExpectedAudience — unrelated hunk (§0)

**Config surface** (all default-off → `anchor_mode=off` = P2.3.2.1):
`gateway_anchor_mode=strict|degraded|off`, `gateway_anchor_url`,
`gateway_anchor_pin`, `anchor_catchup=manual|auto`.

---
*Freeze produced per P2.3.3 implementation-freeze review. No code, no
commits, no runtime changes.*

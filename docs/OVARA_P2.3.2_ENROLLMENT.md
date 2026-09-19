# OVARA 2.0 — P2.3.2 Gateway Enrollment, Admission & Removal

Operational lifecycle around the frozen P2.3.1 cryptographic identity.
P2.3.1 proved *possession*; P2.3.2 separates *admission* — a valid
keypair is not, by itself, authorization to join the domain.

```
identity proof (PoP, frozen)
    ↓
admission authorization (grant / TOFU pin)
    ↓
registry commit (atomic consume + key bind)
    ↓
ACTIVE
```

## 1. Files

| File | Change |
|---|---|
| `internal/gwidentity/store.go` | `GrantRecord`, `kind`-tagged journal lines, `Authorize`/`Deny`/`Admit`/`GrantsFor`/`AllGateways`/`Usable`, grants index, `Open`/`OpenExisting` with 0600 enforcement + grant-id uniqueness |
| `internal/gwidentity/admit_test.go` | 14 adversarial admission tests |
| `internal/gwidentity/hardening_test.go` | 11 P2.3.2.1 regression tests (65 total) |
| `internal/config/config.go` | `gateway_require_admission` (opt-in) |
| `pkg/server/server.go` | `initGatewayTrust` → `Admit` path + admission-mode log |
| `cmd/gwctl/main.go` | operator tool: `grant`/`deny`/`retire`/`list` — read-side commands open without create |
| `tests/e2e/p232_harness.py` | 29-case clean-room e2e |

## 2. Admission model

**Grant** = an operator-written record in the *same* append-only JSONL
registry (`"kind":"grant"`): `{grant_id, gateway_id, public_key?,
state, created_at, expires_at?, consumed_at?}`.

- `authorized` = PENDING admission
- `consumed` = spent (single-use)
- `denied` = REJECTED
- no records = UNENROLLED; usable key record = ACTIVE; `destroyed` =
  RETIRED (terminal tombstone, P2.3.1 semantics — history preserved,
  nothing rewritten)

A second store was deliberately not introduced: grant-consume and
key-bind commit in **one `mutate` under one flock** — atomicity is the
invariant ("never two conflicting authoritative admissions").

**Registry file = authority boundary (P2.3.2.1, audit F1).** Opening
enforces owner-only permissions: new files are `0600`; an existing
file with any `0077` bit set is **refused** — fail closed, no silent
chmod. Before this check, a pre-existing world/group-writable registry
let any local user append a forged `authorized` grant → admitted
(demonstrated exploit, now dead). Grant records stay unsigned: within
the single-filesystem domain, write access to the file IS the
authority; a signature key would live on the same filesystem.

**`grant_id` is globally unique (P2.3.2.1, audit F4).** One id carries
exactly one definition — `gateway_id` + pinned pubkey. Replaying the
same definition folds idempotently (legitimate state transitions
still apply); redefining an id for a different gateway or pin is a
conflict — the journal fails closed on load, and `Authorize` retries
its random id on collision at write time.

**Read-side tooling does not create authority (P2.3.2.1, audit F6).**
`gwctl list`/`deny`/`retire` open the registry via `OpenExisting` —
a missing path errors, it is never created. `gwctl grant` still
initializes a missing registry (that IS its purpose).

`kind` tagging: new key lines write `kind:"key"`; pre-P2.3.2 files
have untagged lines and parse identically. Go ignores unknown JSON
fields, so a frozen P2.3.1 binary reads `kind:"key"` lines fine;
`kind:"grant"` lines fail closed under it (missing key_id → corrupt
→ refuse). Correct downgrade behavior.

## 3. Admit decision order (inside one locked mutate)

1. all records destroyed → `ErrGatewayDestroyed` — tombstone is
   terminal, pending grants cannot help
2. same pub already bound (non-destroyed) → **adopt** — the binding IS
   the earlier admission; restarts need no re-authorization
3. other records exist → `ErrGatewayConflict` (P2.3.1 rule preserved)
4. matching denied grant (unpinned deny, or pinned to this pub) →
   refused — explicit deny beats everything, including compat mode
5. authorized + unexpired + pub-matching grant → **consume + register
   atomically**
6. else → `allowUngranted ? register : ErrUnauthorized`

`allowUngranted` = `!gateway_require_admission || tofu-pin-matched`.
The TOFU pin (frozen P2.3.1 mechanism) counts as admission
authorization — a mismatched pin already fails before Admit.

## 4. Authority separation (E8)

`Authorize`/`Deny`/`Destroy` are callable only through `cmd/gwctl` —
a separate operator binary. The gateway server binary contains **no**
grant-creation path: its boot only *consumes* via `Admit`. A gateway
cannot mint its own admission. Within a single-filesystem trust
domain, grant records are unsigned by design — a "signing key" would
live in the same filesystem and add nothing; admission authority =
write access to the domain registry, the same boundary as every prior
store. Federated/signed enrollment is deferred.

## 5. First-boot / compat behavior

`gateway_require_admission` unset → P2.3.1 behavior preserved
(first-binding wins). The startup log says
`admission=open-first-binding (compat — NOT domain admission)` —
the compat mode cannot be mistaken for a domain admission guarantee.
Set → only grant-or-pin admits a NEW identity; existing bindings still
adopt (grandfathered — admission gates *new* bindings, not restarts).

In-memory registry + require_admission: `gwctl` cannot reach another
process's memory → only TOFU-pin admission is possible; without a pin
the gateway refuses. Documented, not weakened.

## 6. Removal

`gwctl retire` → `Destroy` tombstone (all keys → destroyed, terminal).
Survives restart/SIGKILL (durable record). Old enrollment file, old
key, fresh key under the same gw_id, outstanding grants, and rotation
all refuse afterward — e2e-verified. Historical records and receipts
are untouched (append-only).

## 7. Replay & expiry

Consumed grant → terminal; re-presenting it for a new key → refused
(conflict on existing binding, or no authorization if rolled back —
see limits). `expires_at` optional; zero = no expiry (documented —
not an invented property). Expired grant → refuse.

## 8. Crash semantics

Single-mutate commit → torn tail truncates on next absorb →
either the full admission or none. A crashed admission never produces
a half-admitted gateway. Retirement is one append → durable.
Interrupted grant write → same torn-tail rule.

## 9. Verification

- 54/54 unit tests (14 new admission tests: deny/expiry/pin/consume-
  replay/retired-beats-grant/rotate-can't-bootstrap/one-winner race/
  atomic persistence/mixed-kind file).
- 29/29 e2e: real gateway + gwctl binaries, probe-boot → grant →
  admit workflow, deny/expiry/scope/pin, retirement attacks A–E,
  concurrent admit race, corrupt registry, in-memory+pin, compat.
- Frozen: RC1 46/46, P2.1 7/7, P2.2 21/21 + gate 37/37, P2.3.1
  e2e 22/22. `-race` clean.

## 10. History integrity — what is and is not detected

Four distinct properties; do not conflate them:

| Event | Behavior |
|---|---|
| A. Torn tail (crash mid-append) | Truncated on load — never committed. **VERIFIED** |
| B. In-process shrink below committed offset | Detected; all ops fail closed. **VERIFIED** |
| C. In-process aligned rewrite (replacement ≥ offset, record boundary at offset) | **NOT detected** — injected records fold in (demonstrated). **ARCHITECTURAL LIMITATION** |
| D. Registry restore/replacement while stopped (old snapshot or prefix) | **NOT prevented** — replacement is authoritative on restart. **ARCHITECTURAL LIMITATION** |

Consequences of D, demonstrated in the audit:

- restore → pre-consumption snapshot: a **consumed grant replays**
- restore → pre-retirement snapshot: a **retired gateway resurrects**
- prefix-truncate + restart: earlier history becomes authoritative

**Rollback resistance is an ARCHITECTURAL LIMITATION — anchoring
deferred (P2.3 D-17).** Nothing in this phase claims otherwise.
"Secure within the current trust/history model" ≠ "secure against
replacement of the authority history" — they are different properties.

**F3 — grant-state regression via record duplication/reorder:**
last-wins folding lets a re-appended `authorized` line restore a
`consumed` grant to pending. Left as a **documented journal-model
limitation (LOW)**, not fixed: enforcing state monotonicity in the
fold would conflate a legitimate journal replay with an injected
reorder — indistinguishable without the continuity anchoring that is
deliberately deferred. Not independently sufficient for authority
resurrection: a regressed grant only completes an attack when
combined with key-state rollback (D), which is already the governing
limitation.

## 11. Security claim matrix (P2.3.2.1)

| Claim | Status |
|---|---|
| PoP (possession proof) | VERIFIED |
| Grant authenticity | NOT PROVEN — unsigned by design (fs authority) |
| Grant authority isolation | VERIFIED — gwctl-only mint path + 0600 enforcement |
| Grant replay protection | PARTIALLY VERIFIED — terminal in fold; replays across D |
| Gateway identity binding | VERIFIED |
| Gateway key binding | VERIFIED |
| TOFU integrity | VERIFIED |
| TOFU bootstrap security | PARTIALLY VERIFIED — open compat mode is first-wins |
| Retirement finality | PARTIALLY VERIFIED — resurrects across D |
| Rollback resistance | ARCHITECTURAL LIMITATION — anchoring deferred |
| Crash consistency | VERIFIED |
| Journal integrity | ARCHITECTURAL LIMITATION |
| Journal continuity | ARCHITECTURAL LIMITATION |
| Journal completeness | VERIFIED — per the append-fold model |
| Concurrent admission | VERIFIED |
| Domain isolation | ARCHITECTURAL LIMITATION — file = domain, no crypto domain id |
| Operator-tool authority | VERIFIED — after F1 perm enforcement |

## 12. Other residual limitations (preserved, not claimed away)

Software-key clone limit; in-memory compat mode; stateless PoP
freshness is caller's duty; TPM deferred; issuer/delegation
revocation → P2.3.3; receipt signing → P2.3.5; proxy pinning → later;
federated enrollment service deferred.

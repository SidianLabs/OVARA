# OVARA 2.0 — P2.3.1 Cryptographic Gateway Identity

Implementation of the ratified P2.3 design, phase 1: gateway key +
domain registry + proof of possession. This document covers only what
P2.3.1 built. Issuer/delegation revocation (P2.3.3), staleness epochs
(P2.3.5), proxy pinning, receipt signatures, replication, TPM, and
federated enrollment are **not** implemented here.

## 1. What changed

The gateway trust model before P2.3.1:

```
enrollment.json → self-generated gw_<id> → string compare → trust
```

After P2.3.1:

```
enrollment gw_id → registered ed25519 public key → proof of possession
                → authenticated gateway identity → audience binding
```

`gw_<id>` remains the audience identifier. Canonicalization is
untouched. The audience value is still a string; what changed is that
the endpoint can now *prove* it owns that string via a registered key.

## 2. Files

| File | Role |
|---|---|
| `runtime/gateway/internal/gwidentity/store.go` | Domain registry: JSONL + flock, register/lookup/rotate/revoke/destroy, conflict detection, `AuthenticatePeer` |
| `runtime/gateway/internal/gwidentity/pop.go` | PoP: domain-separated challenge signing + verification |
| `runtime/gateway/internal/gwidentity/keyfile.go` | Private key file: load/create, `0600` enforcement, atomic persist |
| `runtime/gateway/internal/gwidentity/*_test.go` | 40 adversarial unit tests |
| `runtime/gateway/internal/config/config.go` | 6 new optional fields (§6) |
| `runtime/gateway/pkg/server/server.go` | `initGatewayTrust` bootstrap before serving |
| `tests/e2e/p231_harness.py` | 22-case clean-room e2e |

## 3. Gateway identity record

Append-oriented JSONL records (`gwreg.jsonl`):

```json
{"gateway_id":"gw_…","key_id":"gwk_<sha256(pub)[:16]>","public_key":"<hex>",
 "state":"active|rotating|superseded|revoked|destroyed",
 "created_at":…,"activated_at":…,"rotating_until":…,"revoked_at":…,
 "destroyed_at":…,"generation":N}
```

Records are appended, never rewritten — history is preserved so
superseded keys can still verify historical signatures (G6).

The **private key is never in the registry** — public material only.
The private key lives in `gateway_key` (hex ed25519 seed), mode `0600`,
created atomically, loaded with a permission check that refuses
group/world-readable files.

## 4. Proof of possession

```
sig = ed25519.Sign(priv,
    lp("OVARA-GATEWAY-POP-V1") ‖ lp(gateway_id) ‖ lp(key_id) ‖ lp(challenge))
```

- `challenge` = 32 bytes from `crypto/rand`, fresh per authentication.
- Length-prefixed fields — no ambiguous concatenation.
- `Registry.AuthenticatePeer(gw_id, key_id, challenge, sig)` verifies:
  gateway known, key registered to it, key usable (state + grace
  window), signature valid.
- A claimed `gw_id` without a valid signature fails. A valid signature
  under an unregistered/revoked/superseded/destroyed key fails. A
  challenge minted for G1 cannot authenticate G2 (bound into the
  signed bytes).

This is the single authoritative primitive — `AuthenticateGatewayPeer`
equivalent — reusable by future gateway-to-gateway, proxy-pinning, and
revocation-propagation paths. No parallel trust path was added.

## 5. Startup flow (`initGatewayTrust`)

Before serving traffic:

1. Read `gw_id` from enrollment (unchanged mechanism — enrollment owns
   the ID; trust bootstrap never generates one).
2. Load or generate the key file (`0600` enforced) — or an ephemeral
   key if `gateway_key_file` unset.
3. Enforce TOFU pins if configured (`gateway_expected_id` +
   `gateway_expected_pubkey` must be set together; mismatch → fatal).
4. Open the registry: `gateway_registry_file` set → durable JSONL;
   unset → in-memory.
5. Adopt / register / rotate:
   - key already bound to this `gw_id` and usable → adopt (restart path)
   - key bound but dead (revoked/superseded/destroyed) → **refuse** —
     never resurrect a dead key
   - `gateway_force_rekey` + new key → rotate old key into grace
   - otherwise → register (conflict on duplicate `gw_id` → fatal)
6. Require ≥1 usable key (last-key revocation → cannot serve).
7. PoP self-check against the registry.

Every durable-mode failure is fatal: corrupt registry, dead key,
conflict, pin mismatch, missing usable key → `log.Fatal`, no serve.

## 6. Configuration (all optional, additive)

```json
"gateway_registry_file":   "var/data/gwreg.jsonl",
"gateway_key_file":        "var/data/gateway_key",
"gateway_expected_id":     "gw_…",
"gateway_expected_pubkey": "<hex>",
"gateway_force_rekey":     false,
"gateway_key_grace_seconds": 60
```

- Nothing set → in-memory registry + ephemeral key: full PoP self-check
  still runs, but identity does not persist. RC1-compatible default.
- `gateway_registry_file` without `gateway_key_file` is legal but the
  key won't persist across restarts → next boot registers a *new* key →
  **conflict with the old registration** → startup refusal. Operators
  enabling durable trust should set both. (This is the fail-closed
  behavior, not a bug: a durable registry that loses its key *should*
  refuse rather than silently re-key — silent re-keying would defeat
  clone detection.)
- Grace bounds: default 60s, max 24h — same policy constants as the
  P2.2 credential registry.

## 7. Duplicate ID / clone detection

| Same `gw_id` presented with | Registry result |
|---|---|
| same `key_id` + `public_key` | idempotent rejoin |
| different key | **conflict — startup refusal** (both orders tested) |

Two processes racing to register the same `gw_id` with different keys:
flock serializes; first wins, second gets `ErrGatewayConflict`.
Deterministic — one authoritative binding per `gw_id` per domain.

## 8. Key lifecycle

```
generate → ACTIVE →(rotate)→ ROTATING(old) + ACTIVE(new)
                        ↓            ↓
                     SUPERSEDED   REVOKED → DESTROYED
```

- Rotation: new `key_id`, old key enters bounded grace (`ROTATING`,
  usable until `rotating_until`), both can PoP during grace.
- Grace expiry → `SUPERSEDED`: still verifies *historical* signatures
  (records kept), cannot authenticate as active.
- `REVOKED`: dead immediately — overrides rotation grace.
- `DESTROYED`: the `gw_id` itself is tombstoned; register and rotate
  refuse permanently.
- Last-key revocation → `HasUsableKey` false → gateway refuses to serve.

## 9. Migration

Existing RC1 deployments have `enrollment.json` only. Migration is
additive: set `gateway_registry_file` + `gateway_key_file`, restart.
The existing `gw_id` is preserved; a key binds around it. No approvals,
delegations, leases, continuations, receipts, or identity records are
rewritten. If binding cannot be established (conflict, corrupt
registry), startup refuses rather than minting a new `gw_id` — a new
ID would break every audience-scoped artifact.

## 10. Security boundary — stated honestly

**A software keypair provides cryptographic proof of possession but
does not prevent an attacker who clones the complete gateway
filesystem from possessing the same key.** Duplicate identity
conflicts provide *detection* when both instances interact with the
same trust domain (the e2e demonstrates a clone with copied enrollment
+ copied registry but fresh key is refused; a full byte-for-byte clone
including the key file joins — that residual is real and documented,
not hidden). Hardware-backed identity (TPM) is deferred.

Registry rollback is a second documented limit, scoped precisely:

- **Torn tail**: truncated on load — never a committed record.
- **In-process shrink** (file truncated below this process's committed
  offset while running): detected, all operations fail closed.
- **In-process aligned rewrite** (replacement file ≥ committed offset
  with a record boundary at that offset): **NOT detected** — injected
  records fold in. Demonstrated in the P2.3.2 audit.
- **Registry file restore/replacement while stopped** (old snapshot,
  arbitrary prefix): **NOT prevented** — on restart the replacement
  reads as authoritative. Rolled-back revocations, tombstones, and
  consumed grants are lost: a consumed grant replays, a retired or
  previously-destroyed `gw_id` re-registers.

Rollback resistance is an **ARCHITECTURAL LIMITATION — anchoring
deferred** (P2.3 D-17). The trust-domain boundary already assumes
filesystem integrity; this documents the honest consequence.

## 11. Verification

- `internal/gwidentity`: 40 tests — register/idempotent/conflict/
  reverse-order/race, PoP valid+wrong-sig/wrong-key/wrong-gw/wrong-
  keyid/challenge-bound-to-A-fails-for-B/malformed-no-panic, lifecycle
  (rotating-in-grace proves, superseded/revoked/destroyed fail),
  persistence across reopen, torn-tail truncation, corrupt-mid-file
  fail-closed, concurrent mixed ops.
- `tests/e2e/p231_harness.py`: 22/22 — real binaries, SIGKILL restart,
  live clone refusal both directions, full-clone residual, TOFU
  match/mismatch, corrupt registry, unsafe key perms, force_rekey
  rotation + idempotence, private-key absence from logs/registry.
- Frozen suites: RC1 46/46, P2.1 7/7, P2.2 21/21, P2.2 gate 37/37.
- `go test -race` on gwidentity: clean.

## 12. Deferred (not claims)

Issuer revocation, delegation/lease revocation, epoch + min_epoch,
staleness budgets, proxy pubkey pinning, receipt `gateway_sig`,
replication, cross-host replay, external anchoring, TPM, federated
enrollment — P2.3.2 through P2.3.6 or later.

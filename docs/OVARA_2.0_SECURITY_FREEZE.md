# OVARA 2.0 Security Freeze

This is the authoritative security-freeze record for OVARA 2.0. It
follows the final independent security review
(`docs/OVARA_2.0_FINAL_SECURITY_REVIEW.md`) and the post-review
hardening pass that closed its actionable findings.

## Baseline

- Repository commit: recorded in git history at freeze time (post-review
  hardening commit on `main`, after `bddaa03`)
- Branch: `main`

## Security lineage

RC1 → P2.1 → P2.2 → P2.3.1 → P2.3.2 → P2.3.3 → P2.3.4 → P2.3.5 →
P2.3.6 → Final Independent Security Review → Post-review hardening
(F-01 fix, F-02 boundary tests, F-03/F-04/F-05 documentation+tests)

## Final security status

**PASS WITH DOCUMENTED LIMITATIONS**

No CRITICAL or HIGH authorization bypass exists under the documented
threat model. Every path reaching an executor converges through
claim → authority revalidation → executor.

## Verified security properties

All verified against code and adversarially reproduced:

- authenticated principal binding (caller cannot choose identity)
- credential lifecycle enforcement (revoked/expired/superseded/
  suspended → fail closed at authentication)
- delegation chain integrity (signatures, trusted issuers, narrowing,
  audience, expiry, nonce consumption)
- lease binding and revocation
- claim-time authority revalidation (lease + delegation keys + issuers;
  revoked → deny even on forged records)
- approval provenance (only gateway-produced escalated decisions;
  ownership enforced; caller fields rebuilt from server state;
  request-hash + policy-version bound)
- continuation authority preservation across restart, retry, resume,
  drain, and operator sync-execute paths
- executor gating (exactly two call sites, both behind the boundary)
- durable replay protection (journal-backed nonce consumption)
- cross-domain and cross-gateway artifact rejection
- receipt integrity (domain-separated Ed25519, registry-resolved keys,
  historical verification after rotation/revocation)
- gateway trust: enrollment, admission, PoP, key lifecycle
- rollback/equivocation detection within the single-oracle anchor model
  (frozen reconciliation table; strict mode never auto-pushes a
  local-ahead tail)
- fail-closed handling of corrupt trust-domain state
- operator/agent separation (default-deny agent allowlist; ownership
  checks return 404, not existence-revealing 403s)
- identity gate at drain: suspended/retired subjects' queued work never
  executes — including forged records (FR-L1)
- escalation provenance fails closed across restart (FR-M1)
- evidence honesty: failed receipt persistence emits
  `receipt.persist_failed`, never `receipt.issued` (F-01)

## Explicit non-claims

These are NOT guarantees and must not be read as such:

- software keys do not provide clone prevention (duplicate-ID conflict
  detects cloning; it does not prevent filesystem cloning)
- signed receipts do not prove execution truth
- signed receipts do not prove completeness of the event history
- local journals are not externally immutable history
- `trust_epoch` is not global consensus
- revocation does not kill already-running execution
- credential revocation does not freeze already-queued work (identity
  suspension is the freeze control)
- local proof-of-possession is not hardware-rooted gateway identity
- local replay protection is not distributed replay protection
- egress enforcement (I1) depends on the deployed network boundary —
  the software ships `proxy/scripts/setup-egress-boundary.sh` and live
  tests; enforcement exists only where an operator applies it
- filesystem trust-domain assumption (A6) remains load-bearing: an
  attacker who can write gateway state files is operator-equivalent
- continuation/approval queue records are plaintext JSONL and are not
  independently authenticated authority journals (F-03)

## Residual limitations

1. I1 egress is deployment-bounded, not software-bounded.
2. Software-rooted gateway identity (D-08); TPM/hardware deferred.
3. Single trust domain; oracle replication unimplemented (D-13/D-15).
4. Joint registry+oracle rollback = documented trust-root compromise.
5. F-03: execution-queue records lack integrity binding (deferred
   hardening — see below).
6. F-04: in-flight escalations are lost on restart (fail-closed;
   availability-only).
7. F-05: credential revocation does not freeze queued work.
8. Replay-journal deletion resurrects nonces (local-journal residual).
9. Host executors run `sh -c` on the gateway host — the executor
   surface is the blast radius; `shell.sandboxed` exists for isolation.
10. Evidence completeness still depends on store health; failure is
    now honestly reported (F-01) rather than hidden, but a failed
    write remains a missing receipt.

## Deferred hardening

**F-03 — continuation/approval record integrity.** Cryptographically
bind each queued record to the gateway key (HMAC or Ed25519 signature
over the canonical record at write, verified at load). Converts silent
trust-domain tamper into startup refuse/quarantine. Requires a key
dependency in the store layer and a migration story for unsigned
records — deliberately deferred rather than rushed into the freeze.

## Frozen tests

Frozen harnesses (must stay green):

| Suite | Checks |
|-------|--------|
| rc1_harness | 46 |
| p21_harness | 7 |
| p22_harness | 21 |
| p22_gate_harness | 37 |
| p231_harness | 22 |
| p232_harness | 35 |
| p233_harness | 65 |
| p234_harness | 44 |
| p235_harness | 43 |
| p236_harness | 56 |
| **frozen total** | **376** |

Independent adversarial suite (`tests/e2e/final_review.py`): 34 checks.
Boundary tests: `tests/boundary/netns_test.sh` (4 assertions),
`tests/boundary/docker_test.sh` (3 assertions) — live-environment
tests; SKIP when prerequisites are absent.
Unit regression: `internal/handlers/receipt_persist_test.go` (F-01).

## Change policy

Any change to the following reopens security review — the frozen
baseline must not be silently modified:

- identity and credential lifecycle (`internal/idregistry`, auth middleware)
- delegation validation (`internal/evaluator`, identity chain logic)
- revocation (`internal/revocation`, claim-time `CheckClaimAuthority`)
- claim/execution (`internal/continuation`, `internal/execution`, all
  executor call sites)
- persistence formats and stores (any `var/data` journal)
- receipts (`internal/receipt`, `internal/receipts`)
- network boundary (`proxy/`, `setup-egress-boundary.sh`)
- gateway trust (`internal/gwidentity`, `internal/enrollment`)
- anchor/oracle (`internal/anchor`, `reconcileAnchor`)

A change to any of these requires: updated threat-model entry,
adversarial test, and explicit re-review sign-off.

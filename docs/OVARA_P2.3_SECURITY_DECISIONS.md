# OVARA P2.3 — SECURITY DECISIONS

Extends `OVARA_P2_SECURITY_DECISIONS.md` (D-01..D-10). Status values:
`OPEN`, `LEANS`, `REQUIRED-BY-INVARIANT`, `RATIFIED` (accepted for
implementation), `DEFERRED`. Decisions marked RATIFIED here are
recommendations to the reviewer — nothing implements until the design
is accepted.

---

## D-08 Gateway cryptographic identity — RATIFYING AS REQUIRED

- **Question**: is `gw_id` backed by a keypair?
- **Options**: (a) ID-only (RC1); (b) ed25519 software keypair;
  (c) certificate-backed; (d) TPM/hardware; (e) software+attestation.
- **Security consequence**: (a) leaves T-ENROLL-CLONE fully open and
  keeps I6 a name-match. (b) closes I6 as a *cryptographic* property —
  PoP, signed evidence, revocable keys — but does NOT stop a
  full-filesystem clone (the key file copies like the JSON did); it
  makes cloning *detectable* (duplicate-ID conflict) rather than
  silently valid. (c) needs a PKI most deployments lack. (d) is the
  only true clone-resistance, needs hardware. (e) combines (b)+(d)
  costs.
- **Operational consequence**: (b) = key file + registry file, zero
  deps. (d/e) = hardware inventory.
- **Failure mode**: (b) key theft → revoke key, gateway halts, re-key
  via operator. (d) TPM unavailable → can't deploy.
- **Recommendation**: **(b) RATIFIED — REQUIRED-BY-INVARIANT for I6.**
  (d) recorded as an optional deployment-hardening layer, DEFERRED —
  it upgrades clone-*detection* to clone-*resistance*.
- **Status**: RATIFIED (b); (d) DEFERRED.

## D-11 Issuer revocation model

- **Question**: how is an issuer killed at runtime?
- **Options**: (a) config removal + restart only (RC1); (b) revocation
  store entries `class=issuer, id=issuer_id` checked in eval order
  crypto→revocation→semantics; (c) external revocation service.
- **Security consequence**: (a) revocation latency = restart window
  and requires config access — too slow for compromise response, and
  does nothing to already-issued artifacts without per-artifact
  checks. (b) runtime kill inside the domain; every hop of every
  chain dies with the issuer (§8 derivation). (c) same semantics,
  wider reach, new SPOF + staleness surface.
- **Operational consequence**: (b) one more flock file; (c) a service.
- **Failure mode**: (b) store unreadable → startup refusal (fail
  closed); (c) unreachable → stale→escalate path.
- **Recommendation**: **(b) RATIFIED** for the embedded trust domain;
  (c) designed-for via signed statements, not implemented.
- **Status**: RATIFIED (b).

## D-12 Delegation revocation model

- **Question**: how is a single delegation artifact killed?
- **Options**: (a) none — rely on expiry (RC1); (b) revoke by
  presentation key `sha256(lp(issuer)‖lp(nonce))` — the P2.1 replay
  identity; (c) add `chain_id` field to signed payload; (d) edge-level
  revocation (`all A→B`).
- **Security consequence**: (a) "minted but never used" artifacts are
  unkillable until expiry — a real containment hole post-P2.2.
  (b) artifact-granular kill with ZERO format change. (c) changes
  canonicalization — breaks frozen semantics + interop for marginal
  benefit (the nonce already identifies the artifact). (d) broader
  blast radius; complexity for a rarer operation.
- **Operational consequence**: (b) reuses the revocation store;
  (c) touches every signer/verifier.
- **Failure mode**: (b) same as D-11.
- **Recommendation**: **(b) RATIFIED**; (d) recorded as future
  extension if threat review demands edge-granularity.
- **Status**: RATIFIED (b); (d) OPEN as extension.

## D-13 Revocation propagation

- **Question**: how do revocations reach gateways?
- **Options**: (a) shared flock file within the domain (embedded);
  (b) replicated signed statements (pull-based); (c) push/event bus.
- **Security consequence**: (a) propagation = write commit — strongest
  possible within-domain, trivially correct. (b) bounded staleness,
  works cross-host — the documented future domain. (c) lowest latency,
  most machinery.
- **Operational consequence**: (a) zero new infra; (b) sync protocol;
  (c) a bus.
- **Failure mode**: (a) file failure → deny at startup; (b) partition →
  stale → escalate; (c) bus down → same stale path.
- **Recommendation**: **(a) RATIFIED** — matches the P2.1/P2.2 trust-
  domain definition exactly; (b) is the designed-for cross-domain
  path, explicitly not implemented.
- **Status**: RATIFIED (a).

## D-14 Staleness budget

- **Question**: how old may a revocation view be?
- **Options**: embedded-zero (shared file) / 30s / 120s / minutes.
- **Security consequence**: embedded mode makes the budget vacuous
  (reads see last committed write) — the honest answer for what is
  being built. External mode needs a number: 30s default matches
  D-10's earlier lean and keeps compromise response meaningful.
- **Operational consequence**: tighter = more load + more stale-
  escalate events during outages.
- **Failure mode**: budget exceeded → escalate (capability requests);
  epoch regression → fail closed.
- **Recommendation**: **RATIFIED** — embedded = zero-by-construction;
  `staleness_budget` config (default 30s, operator-tunable, declared
  max 300s) applies to any future cached/external view; degrade
  action = escalate, never silent allow (D-03 ratified alongside).
- **Status**: RATIFIED.

## D-15 Multi-gateway trust domain

- **Question**: what does "the domain" mean when several gateways
  exist?
- **Options**: (a) domain = shared filesystem (all stores flock-shared)
  — the implemented boundary; (b) domain = replicated statement set
  (cross-host) — designed, unimplemented; (c) domain = consensus
  cluster — not evaluated for P2.3.
- **Security consequence**: (a) eliminates intra-domain split-brain by
  construction; cross-domain replay bounded by audience scoping, not
  shared consume — consistent with P2.1's explicit non-claim.
- **Operational consequence**: (a) multiple gateway processes on one
  host / shared volume; (b) sync infra; (c) quorum infra.
- **Failure mode**: (a) shared-volume failure = domain down (documented
  SPOF of the deployment model); (b) partition → per-domain epochs
  diverge → escalate on min_epoch citations.
- **Recommendation**: **(a) RATIFIED** as the implemented claim;
  language everywhere must say "trust domain = shared state files,"
  never "cluster."
- **Status**: RATIFIED (a).

## D-16 Gateway key lifecycle

- **Question**: key states + artifact effects?
- **Options**: (a) single key, replace-on-theft (restart everything);
  (b) full lifecycle GENERATE→ACTIVE→ROTATING→SUPERSEDED→REVOKED→
  DESTROYED with grace + key history.
- **Security consequence**: (a) rotation = flag day; stolen key can't
  be killed without renaming the gateway. (b) rotation is seamless
  (audience binds to identity not key); revocation kills PoP while
  history stays verifiable — revocation never rewrites evidence.
- **Operational consequence**: (b) key-history table in the registry.
- **Failure mode**: revoked last key → gateway refuses service
  (fail closed); recovery = operator re-key, never silent.
- **Recommendation**: **(b) RATIFIED** — mirrors the P2.2 credential
  machine deliberately (one pattern, two layers).
- **Status**: RATIFIED (b).

## D-17 Trust-state rollback detection

- **Question**: can restored/replaced trust files be detected?
- **Options**: (a) none — accept rollback (P2.1 documented residual);
  (b) domain epoch monotonicity — a regressed epoch = tamper → fail
  closed + CRITICAL; (c) external anchoring of epoch heads.
- **Security consequence**: (a) silent resurrection of revoked state.
  (b) detects rollback *only if the attacker didn't also restore the
  epoch* — file-level rollback of the whole directory is still
  invisible (honest bound). (c) real detection, needs the anchor
  milestone.
- **Operational consequence**: (b) one counter in the store header;
  (c) anchor service.
- **Failure mode**: (b) regression → startup refusal + CRITICAL event.
- **Recommendation**: **(b) RATIFIED** as the local floor — detects
  surgical rollbacks and makes whole-file rollback *at least*
  epoch-consistent rather than trivially mixed; **(c) DEFERRED** to
  the anchoring milestone — whole-directory rollback remains a
  documented residual until then.
- **Status**: RATIFIED (b); (c) DEFERRED.

---

## Decision summary

| # | decision | status |
|---|---|---|
| D-08 | ed25519 software gateway keypair; TPM layer deferred | RATIFIED (required for I6) |
| D-11 | issuer revocation via domain revocation store | RATIFIED |
| D-12 | delegation revocation by presentation key (no format change) | RATIFIED |
| D-13 | shared-flock propagation within domain; replication designed not built | RATIFIED |
| D-14 | embedded zero staleness; 30s budget for cached/external views | RATIFIED |
| D-15 | trust domain = shared state files; no cluster claims | RATIFIED |
| D-16 | full key lifecycle + preserved key history | RATIFIED |
| D-17 | epoch monotonicity now; anchored detection deferred | RATIFIED/DEFERRED |

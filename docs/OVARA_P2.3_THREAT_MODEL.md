# OVARA P2.3 — GATEWAY TRUST + REVOCATION PROPAGATION: THREAT MODEL

Design-phase companion to `OVARA_P2.3_GATEWAY_TRUST_REVOCATION_DESIGN.md`.
Extends `OVARA_P2_THREAT_MODEL.md`; RC1/P2.1/P2.2 are frozen baselines.
This document is design-only — no production code changes are implied.

---

## 1. CURRENT TRUST SURFACE (verified by inspection)

| Component | Current mechanism | Cryptographic? | Clone resistance |
|---|---|---|---|
| Gateway identity | `enrollment.json`: self-generated `gw_<ms><rand>`, atomic file write | none — random string | none — file copy clones the identity |
| Audience binding | string compare: `expectedAudience` (the gw_ name) vs `lease.audience` / `hop.audience` | name-match only | cloned name validates on the clone |
| Issuer trust | `trusted_issuers` config: issuer_id → hex ed25519 pubkey, loaded at startup | signature verify per artifact | key mgmt is config+restart only |
| Issuer revocation | config removal + restart | n/a | no runtime path, no epoch, no statement |
| Delegation revocation | none (expiry + P2.1 replay only) | n/a | n/a |
| Lease revocation | `IsRevoked(lease_id)` on TRACKED leases; file store optional | store entry | untracked leases unaffected |
| Receipt signature | HMAC-SHA256, `receipt_signing_key` in config | symmetric | anyone with config forges receipts |
| Proxy → gateway | `gateway_url` + `agent_token` in proxy config | bearer token only | no gateway identity pinning (plain HTTP) |
| Federation | `FederatedTrustClient` stub → `/v1/identities/verify` | signature field exists | unwired |
| Identity/credential revocation | P2.2 idregistry (flock+JSONL, durable) | sha256 fingerprints | filesystem = trust domain |

## 2. THREATS IN SCOPE

### T-ENROLL-CLONE (existing, P2.3 must bound honestly)

Attacker copies `enrollment.json` (+ config + state) to a second machine.
Today: clone has identical `gw_id` → every audience-bound artifact
validates there. **Hard truth for the design**: a *software* key file is
equally copyable — cloning resistance cannot come from key possession
alone. What a keypair adds: proof-of-possession challenges, signed
evidence, key rotation/revocation, and a registry-visible identity that
makes a duplicate-ID clone *detectable* (conflicting check-ins) rather
than silently valid. Full clone resistance requires hardware binding
(TPM) — evaluated, deferred as deployment-level option.

### T-GATEWAY-IMPERSONATION

Attacker registers `gw_id` it does not own (squatting) or claims a
trusted gw_id in a registry. Control needed: enrollment requires
proof-of-possession of the private key bound to the claimed ID.

### T-KEY-THEFT

Gateway private key exfiltrated (without full filesystem clone — e.g.
config backup leak). Control: key revocation + rotation with defined
artifact semantics; detection via registry check-in conflicts.

### T-ISSUER-COMPROMISE

Delegation/lease issuer ed25519 key compromised. Today: no runtime
revocation — config edit + restart, and pre-issued artifacts keep
verifying until expiry. Control: signed revocation statement + epoch +
evaluator check ordering.

### T-DELEGATION-REPLAY-ESCAPE

Revoked delegation re-presented. P2.1 kills re-presentation of the SAME
signed artifact; it does NOT cover "delegation was minted, never used,
now must die" — that is the revocation-store gap P2.3 fills.

### T-REVOCATION-SUPPRESSION

Attacker (or partition) prevents a gateway from learning a revocation.
Control: staleness budget + degrade-toward-safe (escalate), never
silent-allow on capability-bearing requests.

### T-TRUST-ROLLBACK

Backup-restore or file-replacement of the revocation store resurrects
revoked issuers/delegations. Same class as P2.1 journal rollback —
undetectable locally without anchoring; mitigated by epoch monotonicity
(higher observed epoch must never regress) + documented residual.

### T-SPLIT-BRAIN-CONSUME

Two gateways with separate state each consume the same single-use
capability. P2.1 explicitly does NOT claim cross-host protection.
P2.3's answer is the trust-domain boundary + audience scoping, not a
distributed consume — documented, not silently expanded.

### T-AUDIENCE-SUBSTITUTION

Capability minted for G1 presented to G2. Name-match today stops the
naive case; with crypto identity the check becomes "does THIS gateway
possess the key bound to the claimed audience" — a clone that copied
the key still passes (honest residual).

### T-STALE-APPROVAL / T-STALE-CONTINUATION

Approval granted or continuation queued while authorization was valid,
executed after the underlying capability/issuer/identity died. P2.2
gated identity at claim; P2.3 must re-check capability/issuer
revocation at the same enforcement point.

### T-ENROLLMENT-REPLAY / T-ENROLLMENT-THEFT

Enrollment credential replayed to register a second gateway, or stolen
enrollment token used off-box. Control: single-use enrollment
credentials + PoP binding enrollment to the generated key, not the
machine.

### T-SIBLING-DOMAIN CONFUSION

Two gateways with separate state files believing they share a trust
domain. Control: trust domain is defined by shared state files —
audience scoping keeps separate domains from honoring each other's
artifacts regardless of belief.

## 3. TRUST ASSUMPTIONS (explicit)

- The filesystem hosting `enrollment.json`, gateway key file,
  `identity_registry`, `replay journal`, `revocation store` IS the
  trust domain boundary. Whoever controls it controls the domain —
  same assumption class as P2.1/P2.2.
- Operator tokens remain the administrative root for lifecycle
  operations (until D-09's registry/issuer separation is built).
- Clock skew inside a domain is bounded (epocHs/staleness budgets
  assume sane clocks; clock attack is a documented residual).
- An agent can never reach these files (RC1 capability-separation
  assumption — unchanged).

## 4. OUT OF SCOPE (stated, not silently dropped)

- TPM/hardware attestation (Option C evaluated; deferred — deployment
  hardening, not required for the invariants as scoped)
- Cross-host / cross-domain distributed revocation consensus
- Distributed replay (P2.1 boundary unchanged)
- Multi-tenant partitioning (I18 stays out of scope)
- Receipt anchoring implementation (interaction design only)
- Running-execution retroactive kill (documented non-goal, carried
  forward from P2)

## 5. THREAT → INVARIANT MAP

| Threat | Invariant(s) engaged |
|---|---|
| T-ENROLL-CLONE | I6, G2 (uniqueness) |
| T-GATEWAY-IMPERSONATION | G1, G4 |
| T-KEY-THEFT | G5, I13 |
| T-ISSUER-COMPROMISE | G6, I5, I20 |
| T-DELEGATION-REPLAY-ESCAPE | G7, I11 |
| T-REVOCATION-SUPPRESSION | G8, G9, I19, I20 |
| T-TRUST-ROLLBACK | G11, I20 |
| T-SPLIT-BRAIN-CONSUME | G10, G12, I11 |
| T-AUDIENCE-SUBSTITUTION | G3, I6, I17 |
| T-STALE-APPROVAL/CONTINUATION | G7, G8, I10 |
| T-ENROLLMENT-REPLAY/THEFT | G4 |
| T-SIBLING-DOMAIN | G12, I6 |

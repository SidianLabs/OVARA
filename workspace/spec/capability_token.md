# Spec: Capability token format + signed requests (v0.9)

Goals: (a) capabilities are signed, attenuable, delegation-safe tokens;
(b) ActionRequests themselves are unforgeable below the auth layer —
closes v1 audit-F4 (unsigned requests) + SEC-0021's "replay protection
moot" residual.

## 1. Format choice

**Biscuit-style attenuable tokens over raw Ed25519-envelope** —
evaluated against macaroon:

| Candidate | Verdict |
|---|---|
| Macaroon (HMAC chain) | Caveat attenuation is proven; but verification needs the root secret → verifier is inside the issuer domain. OK for same-service, wrong for cross-boundary delegation proofs |
| **Biscuit** (public-key, datalog authorization) | Take: public-key verification + third-party attenuation + built-in policy datalog. Token verifies offline — fits "verify on a second machine" (P8 pattern) |
| Plain JWT + caveats | Skip: attenuation is non-standard, everyone reinvents it |

[ASSUMED: biscuit-go maturity acceptable; if not, fall back to
macaroon-shaped Ed25519 envelope with embedded caveat list — decide
in Phase 2 spike, record in DECISIONS.md.]

## 2. Token anatomy

```
Token := {
  authority: { issuer, subject, grants: Scope[], constraints: Caveat[],
               expiry, quota, delegation_depth_left }
  blocks:    [ AttenuationBlock* ]   # each narrows, never widens (P4)
  signatures: chained Ed25519
}
Scope := { action_types: GlobEnum, resources: CanonicalPattern[],
           env: EnvSet, rate: Quota }
Caveat := time-bound | env-bound | nonce-bound | taint-floor
```

Invariants enforced at *verification* (not issuance):
- `scope(b_i+1) ⊆ scope(b_i)` — attenuation monotone (P4 property test)
- `expiry(b_i+1) ≤ expiry(b_i)` — time monotone
- `delegation_depth` decrements; 0 → token can't delegate (P5)
- `taint_floor` can only rise — a token minted for clean contexts
  can't be exercised by tainted proposals (P5 hook)

## 3. Signed ActionRequests (the F4 fix)

Every request the runtime accepts carries:

```
SignedRequest := {
  action:    canonical Action (spec/action_model.md)
  capability: Token
  request_sig: Ed25519 over sha256(action_canonical_bytes ‖
                token_bytes ‖ nonce ‖ issued_at)
}
```

Consequences:
- Replay protection becomes *real*: nonce binds into a signature the
  attacker can't recompute (v1: nonce was decorative on unsigned
  requests — SEC-0021).
- subject_id spoofing impossible: request_sig key must match the
  token's subject AND the credential principal (keeps the v1
  identity_mismatch invariant, adds a cryptographic layer).
- Forging escalation requires the private key, not a JSON edit.

Key custody: agent holds a *signing keypair* distinct from operator;
public key registered in the identity registry (v1 already has one —
extend to require per-agent pubkey at enrollment, not just token
seeding). **Key custody rule (spec-review F-SPEC-1):** the enrolled
pubkey arrives via the operator's provisioning channel — an agent can
never self-register or re-key its own identity; re-keying is an
operator action and itself an audited event type.

## 4. Revocation (summary — full spec in revocation_protocol.md)

- Epoch-based: `min_epoch` in Action + token `epoch` field; deny if
  token.epoch < current_epoch.
- Revocation = epoch bump + (push) live token kill list delivered to
  executors; pull path via checkpoint.
- Revocation latency bound is a *measured* number published per
  deployment — not asserted.

## 5. Failure semantics (P2)

- Bad signature / unparseable token / expired / wrong-subject → deny
  with reason code (agent-visible: coarse; operator-visible: exact).
- Missing capability where policy requires one → deny, not escalate
  (escalation is for *policy-level* ambiguity, not missing evidence).
- Token verification is pure + bounded (fuel) — P11 hook.

## 6. Compat

v1 leases become v2 Tokens; v1 `trusted_issuers` config becomes the
issuer trust root list. Migration doc covers: v1 leases lacked
attenuation blocks → treated as depth-0 non-delegatable.

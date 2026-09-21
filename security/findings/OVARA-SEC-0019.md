# OVARA-SEC-0019 — Self-asserted identity → cross-agent trust poisoning, restriction evasion, approval-spam

**Severity:** MEDIUM
**Component:** identity/validator.go:45-67, evaluator risk counting,
trust/shield handlers
**Status:** CONFIRMED (static; consistent with live fake-identity allow)

## Evidence
`subject_id`/`agent_id` are free-form caller strings — `VerifyKey` is
never used, no proof-of-possession. Consequences:
- **Cross-agent DoS**: 3 deny/escalate checks bearing
  `subject_id:"victim"` auto-restrict the victim (or
  `POST /v1/shield/restrict/{anyone}` directly).
- **Proxy-wide DoS**: proxy hardcodes `subject_id:"egress-agent"` —
  poisoning it forces ALL proxied traffic to escalate → approval flood.
- **Evasion**: rotate `subject_id` → risk count resets;
  `/v1/shield/unrestrict/self` resets anyway.
- Restrictions/risk counts are in-memory → restart clears.

## Root cause
Identity is a claim, not a credential.

## Security impact
Trust/shield layer is fully gameable both directions (punish others,
launder self); availability attacks need no privileges beyond API
reach.

## Proposed fix
Bind identity to the caller: per-agent tokens (P1.1 execution identity
gives this to the proxy path), mTLS SAN, or signed attestations;
server-derived agent_id, never request-body.

## Regression test
Checks with forged subject_id must not affect another agent's trust
state; restrict/unrestrict requires operator role + real identity.

## Residual risk
Self-asserted IDs may stay as labels — must not drive security state.

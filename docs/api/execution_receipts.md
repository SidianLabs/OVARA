# Execution Receipts

Execution receipts are signed records proving that a consequential action was
evaluated under a specific identity, capability, policy, and trust context.

## Purpose

Receipts are one of Ovara's core primitives. They are not generic logs. They
exist to answer five questions after the fact:

- who acted
- under what authority
- against what resource
- under what policy and trust state
- with what decision outcome

## Minimum Fields

- receipt id
- action digest
- action type
- resource selector
- agent identity reference
- capability lease reference
- delegation chain hash
- decision outcome
- policy version
- trust context summary
- approval reference if applicable
- issued timestamp
- signature

## Design Rules

- receipts are immutable
- receipts are portable across deployment models
- signatures must be verifiable without querying live mutable state where
  possible
- the receipt format should remain compact enough for routine storage and audit

## V1 Constraints

- receipts reference reasoning metadata, but do not embed full reasoning traces
- trust context is summarized, not modeled as a full raw feature dump
- v1 receipts are optimized for engineering and deployment actions first

## Example Shape

```json
{
  "receipt_id": "rcpt_123",
  "action_digest": "sha256:...",
  "action_type": "github.push",
  "resource": "repo:acme/api:branch/main",
  "agent_id": "agt_123",
  "capability_lease_id": "cap_123",
  "decision": "escalate",
  "policy_version": "pol_42",
  "trust_context": {
    "score": 0.94,
    "environment": "verified"
  },
  "issued_at": "2026-05-24T12:00:00Z",
  "signature": "sig_abc"
}
```

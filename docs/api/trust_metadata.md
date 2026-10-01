# Trust Metadata API

> **Status: designed, not consumed by the V1 gateway.** The
> `TrustMetadata` type exists in the identity module, but the V1
> gateway evaluator does not read posture attestations. The trust score
> that influences decisions is computed from ShieldStore state and
> request-pattern heuristics (see
> [Trust Score Computation](#trust-score-computation) below). This page
> documents the designed attestation format and the actual V1 score.

Trust metadata is the signed posture attestation that agents publish
periodically to indicate their current runtime state.

## Posture Attestation

```json
{
  "agent_id": "agt_001",
  "posture": {
    "isolation": "firecracker",
    "code_version": "1.2.3",
    "seccomp_profile": "default-strict",
    "apparmor_profile": "ovara-gateway",
    "trust_score_hint": 0.85,
    "patch_level": "2026-05-15",
    "uptime_seconds": 3600
  },
  "issued_at": "2026-06-01T00:00:00Z",
  "expires_at": "2026-06-01T01:00:00Z",
  "signature": "ed25519:3045022100..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | The agent this metadata describes |
| `posture` | object | Posture fields (see below) |
| `issued_at` | timestamp | When the attestation was issued |
| `expires_at` | timestamp | When the attestation expires (typically 1 hour) |
| `signature` | string | ed25519 signature over the canonical payload |

## Posture Fields

| Field | Type | Description |
|-------|------|-------------|
| `isolation` | string | Runtime isolation: `none`, `docker`, `firecracker`, `gvisor` |
| `code_version` | string | The agent's code version |
| `seccomp_profile` | string | Name of the active seccomp profile |
| `apparmor_profile` | string | Name of the active AppArmor profile |
| `trust_score_hint` | number | Agent's self-reported trust score (0.0-1.0) |
| `patch_level` | string | Date of last security patch (YYYY-MM-DD) |
| `uptime_seconds` | int | Seconds since agent started |

## Trust Score Computation

The V1 evaluator computes the trust score in
[`trust/evaluator.go`](../../runtime/gateway/internal/trust/evaluator.go).
The score starts at **1.0** and deductions are subtracted for each
observed risk signal:

| Signal | Deduction |
|--------|-----------|
| Agent restricted in ShieldStore | −0.40 |
| Recorded risk events | −0.05 per event |
| Last decision was `deny`/`escalate` within 30s | −0.10 |
| Risky shell pattern in the request | −0.15 per signal |
| Risky git pattern in the request | −0.15 per signal |
| Production environment target | −0.20 |
| Weak lease scope (wildcard `*` scope used for a `shell` action) | −0.10 |
| Delegation chain depth greater than 3 | −0.10 |

The score is clamped to [0.0, 1.0] and mapped to a trust level:

| Score Range | Trust Level |
|-------------|-------------|
| 0.8 - 1.0 | `high` |
| 0.5 - 0.8 | `medium` |
| 0.0 - 0.5 | `low` |
| 0.0 | `none` |

A score below 0.6 activates the shield (`shield_active`); a score below
0.5, or a `low`/`none` level, escalates an otherwise-allowed decision.
Posture fields from TrustMetadata (isolation, patch level,
`trust_score_hint`) do **not** feed this computation in V1 — the
multiplicative formula previously described here was design intent, not
implemented behavior.

## Trust-Dependent Policy Rules

Policies can express rules that depend on trust level:

```json
{
  "action_type": "shell",
  "environment": "production",
  "escalate": true,
  "conditions": {
    "min_trust_score": 0.7
  }
}
```

If the agent's current trust score is below 0.7, this rule escalates
the action for human review. The `min_trust_level` field is a
convenience for the level-based equivalent.

## Drift Detection

The `DriftDetector` analyzes the agent's action patterns over a
sliding window and computes a drift score. If the agent's actions
diverge significantly from its historical pattern, the drift score
rises, reducing trust and triggering escalation.

## Degradation Model

The `DegradationModel` decays trust when risky actions are observed
and recovers trust with clean actions. The model uses exponential
decay with streak acceleration — repeated risky actions decay faster
than isolated ones.

## Chain Detection

The `ChainDetector` identifies suspicious delegation patterns:

- **Self-delegation** — agent delegates to itself
- **Excessive depth** — delegation chain too deep (>10)
- **Issuer concentration** — too many leases from a single issuer
- **Rapid re-delegation** — frequent re-delegation suggests laundering

Suspicious chains are escalated regardless of policy.

## State Persistence

Trust state (drift, degradation, chain detection) is persisted to
disk via the file-backed state store. The state can be exported and
imported for backup or migration between gateways.

## SDK Helpers

```typescript
import { getTrustContext } from '@ovara/sdk';

const context = await client.getTrustContext('agt_001');
// {
//   agent_id: "agt_001",
//   trust_score: 0.85,
//   trust_level: "high",
//   drift_score: 0.05,
//   degradation_score: 0.1,
//   restricted: false
// }
```

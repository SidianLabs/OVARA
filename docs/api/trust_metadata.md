# Trust Metadata API

Trust metadata is the signed posture attestation that agents publish
periodically to indicate their current runtime state. The gateway uses
trust metadata to compute trust scores and make authorization
decisions.

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

The gateway computes a trust score from multiple signals:

```
trust_score = base_score
            * isolation_multiplier
            * patch_freshness
            * drift_penalty
            * degradation_penalty
            + trust_score_hint * 0.1
```

Where:

- `base_score` = 0.5 (neutral)
- `isolation_multiplier`: `none`=1.0, `docker`=1.05, `firecracker`=1.2, `gvisor`=1.15
- `patch_freshness`: 1.0 if patched within 30 days, decaying to 0.5 at 90 days
- `drift_penalty`: 1.0 - 0.5 * drift_score (from DriftDetector)
- `degradation_penalty`: 1.0 - 0.5 * degradation_score (from DegradationModel)

The final score is clamped to [0.0, 1.0] and mapped to a trust level:

| Score Range | Trust Level |
|-------------|-------------|
| 0.8 - 1.0 | `high` |
| 0.5 - 0.8 | `medium` |
| 0.2 - 0.5 | `low` |
| 0.0 - 0.2 | `none` |

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

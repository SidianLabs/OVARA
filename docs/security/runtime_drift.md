# Runtime Drift

Runtime drift is the gradual deviation of an agent's behavior from
its intended pattern over time. It's a particularly insidious threat
because individual actions may be allowed by the policy, but the
cumulative effect is malicious.

## Attack Patterns

### 1. Action Type Shift

An agent starts performing a different mix of action types than
expected (e.g., suddenly starts running many `shell` commands when
it normally only does `git.pull`).

**Defense:** DriftDetector analyzes the distribution of action
types in a sliding window. A significant shift from the historical
distribution increases the drift score.

### 2. Volume Spike

An agent suddenly performs many more actions per hour than usual.

**Defense:** The volume component of the drift score detects
unusual action frequency. Combined with the action type analysis,
this catches "burst" attacks.

### 3. Resource Targeting Shift

An agent starts targeting different resources than its historical
pattern (e.g., suddenly accessing `repo:acme/secrets` when it
normally only touches `repo:acme/api`).

**Defense:** The resource targeting component tracks the distribution
of resource prefixes. A shift triggers drift.

### 4. Time-of-Day Anomaly

An agent that normally runs during business hours suddenly runs at
3am.

**Defense:** Time-of-day is a feature in the drift model. Off-hours
activity is flagged.

### 5. Gradual Trust Erosion

An attacker slowly degrades the agent's trust through repeated
risky-but-allowed actions, hoping to slip past trust-dependent
policies.

**Defense:** The DegradationModel decays trust when risky actions
are observed. Repeated risky actions decay faster (streak
acceleration), making gradual erosion harder.

## Drift Detection Algorithm

The DriftDetector uses a split-window approach:

1. **Baseline window** — older half of the sliding window
2. **Current window** — newer half of the sliding window
3. **Distribution comparison** — compare action type distributions
   using a distance metric (e.g., total variation distance)
4. **Score normalization** — distance is normalized to [0, 1]

```go
type DriftDetector struct {
    windowSize  int           // e.g., 100 actions
    baselineRatio float64     // e.g., 0.5 (older half vs newer half)
}

func (d *DriftDetector) Record(actionType string) {
    d.window = append(d.window, actionType)
    if len(d.window) > d.windowSize {
        d.window = d.window[1:]
    }
}

func (d *DriftDetector) Score() float64 {
    if len(d.window) < d.windowSize {
        return 0.0  // not enough data
    }
    baseline, current := d.splitWindow()
    return d.totalVariationDistance(baseline, current)
}
```

The drift score is then used to adjust the agent's trust score:

```
trust_score = base_score * (1.0 - 0.5 * drift_score)
```

A drift score of 0.5 halves the trust score. A drift score of 1.0
reduces trust to 0.

## Trust Degradation Model

The DegradationModel decays trust when risky actions are observed
and recovers with clean actions:

```go
type DegradationModel struct {
    decayRate    float64  // per risky action
    recoveryRate float64  // per clean action
    streakBoost  float64  // multiplier for consecutive risky actions
    state        map[string]*AgentState
}

func (m *DegradationModel) OnRiskyAction(agentID string) {
    s := m.state[agentID]
    streak := s.currentStreak
    decay := m.decayRate * (1.0 + streak * m.streakBoost)
    s.score = max(0, s.score - decay)
    s.currentStreak++
}

func (m *DegradationModel) OnCleanAction(agentID string) {
    s := m.state[agentID]
    s.score = min(1.0, s.score + m.recoveryRate)
    s.currentStreak = 0  // reset streak
}
```

## State Persistence

Drift and degradation state is persisted to disk via the file-backed
state store. On gateway restart, the state is loaded from disk,
preserving long-term tracking across restarts.

The state can also be exported and imported for backup, migration
between gateways, or cross-instance sync.

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

If the agent's current trust score is below 0.7, the action is
escalated regardless of other policy rules. This provides automatic
containment of drifting agents.

## Testing

```bash
cd runtime/gateway && go test -race -count=1 ./internal/trust/
```

The trust package has comprehensive tests for:

- Drift score computation
- Degradation model decay and recovery
- Streak acceleration
- Trust-dependent policy rules
- State persistence and restoration

## Limitations

- **False positives.** The drift detector may flag legitimate
  changes in behavior (e.g., a new feature rollout that changes
  action patterns). Mitigation: configurable thresholds.
- **Cold start.** The drift detector needs a window of historical
  data before it can score. New agents have a drift score of 0.
- **Single-agent model.** The current implementation tracks drift
  per-agent. Cross-agent drift (e.g., coordinated multi-agent
  attacks) is not detected. This is a V2+ concern.

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Chain Detection](chain_detection.md) — related anomaly detection
- [Trust Metadata API](../api/trust_metadata.md)

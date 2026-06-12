# Capability Chaining Detection

Capability chaining is the pattern of re-delegating capabilities
across multiple agents to obscure the authority source or launder
permissions. The chain detector identifies suspicious patterns.

## Threat Model

In a typical agent ecosystem, an agent A might delegate to B, B
might delegate to C, and so on. The chain forms a tree (or a
graph) of authority. Most chains are legitimate (e.g., a manager
agent delegating to a worker agent). But some chains are
suspicious:

- **Self-delegation** — agent A delegates to itself
- **Excessive depth** — too many hops in the chain
- **Issuer concentration** — too many leases from a single issuer
- **Rapid re-delegation** — frequent re-delegation suggests
  laundering
- **Circular chains** — A → B → A (forged)
- **Cross-org rapid delegation** — quickly moving authority
  between organizations

## Detection Patterns

### 1. Self-Delegation

```go
if chain.issuer == chain.subject {
    return Suspicious("self_delegation")
}
```

A lease where the issuer and subject are the same entity is
suspicious. The agent is essentially granting itself additional
authority.

**Mitigation:** Reject the chain at issuance time. Log the attempt
for review.

### 2. Excessive Depth

```go
if chain.depth > 10 {
    return Suspicious("excessive_depth")
}
```

Chains deeper than 10 hops are unusual and likely indicate
obfuscation. The V1 maximum depth is 10.

**Mitigation:** Reject chains exceeding the maximum depth at
issuance time.

### 3. Issuer Concentration

```go
issuerCounts := countIssuers(leases)
if max(issuerCounts) / total > 0.5 {
    return Suspicious("issuer_concentration")
}
```

If a single issuer is responsible for more than 50% of active
leases, the issuer may be compromised or colluding.

**Mitigation:** Alert the operator. Consider suspending new
leases from the concentrated issuer.

### 4. Rapid Re-delegation

```go
re_delegation_rate := count_re_delegations(agent) / time_period
if re_delegation_rate > 10 {  // 10 re-delegations per hour
    return Suspicious("rapid_re_delegation")
}
```

Frequent re-delegation from the same agent suggests the agent
is rapidly moving authority to obscure its actions.

**Mitigation:** Throttle re-delegation. Alert the operator.

### 5. Circular Chains

```go
if containsCircularReference(chain) {
    return Suspicious("circular_chain")
}
```

A chain that contains a circular reference (A → B → A) is
suspicious. The chain was likely forged.

**Mitigation:** Reject the chain. Investigate the forger.

### 6. Cross-Org Rapid Delegation

```go
if isCrossOrg(chain) && delegation_age < 5 * time.Minute {
    return Suspicious("cross_org_rapid_delegation")
}
```

Delegating authority across organizations and then using it
within 5 minutes suggests the cross-org delegation was for the
specific purpose of this action, possibly to bypass trust
restrictions.

**Mitigation:** Require longer cooldown for cross-org
delegations. Alert the operator.

## Implementation

The chain detector is implemented in
[`trust/internal/chain_detection/`](../../trust/internal/chain_detection/):

- `chain_detection.go` — detection logic
- `chain_detection_test.go` — comprehensive tests

## Integration with Policy

When a chain is flagged as suspicious, the policy evaluation
forces an `escalate` decision:

```go
if chainDetector.IsSuspicious(chain) {
    decision = Escalate
    reason = "suspicious_chain"
}
```

The escalation requires human review, preventing the suspicious
chain from being used without operator awareness.

## Trust Graph Integration

For cross-org chains, the trust graph in
[`trust/internal/graph/`](../../trust/internal/graph/) is used:

- The graph maintains organizations and their trust relationships
- Cross-org trust paths are computed using DFS with bounded depth
- The trust level between organizations affects chain
  evaluation
- Revocation of a trust relationship invalidates all chains
  that depend on it

## Testing

```bash
cd trust && go test -race -count=1 ./internal/chain_detection/
```

The tests cover:

- Self-delegation detection
- Excessive depth detection
- Issuer concentration detection
- Rapid re-delegation detection
- Circular chain detection
- Cross-org rapid delegation detection
- Combined suspicious patterns

## Limitations

- **Heuristic-based.** The detection uses heuristics, not
  formal verification. False positives are possible.
- **Single-gateway scope.** The current implementation analyzes
  chains visible to a single gateway. Cross-gateway patterns
  require the trust server.
- **Reactive, not proactive.** The detector flags suspicious
  chains at evaluation time, not at issuance time. Issuance-
  time checks are a V2+ concern.

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Runtime Drift](runtime_drift.md) — related anomaly detection
- [Machine Identity Attacks](machine_identity_attacks.md)

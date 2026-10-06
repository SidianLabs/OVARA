# Scenario format (JSON, one per file)

```json
{
  "id": "sc-egress-001",
  "class": "egress",
  "tier": "t1",
  "title": "...",
  "setup": {"actor": "ag_x", "policy": "pol_y", "tokens": [...]},
  "request": {"type": "net.egress", "resource": "...", "env": "dev",
              "nonce_mode": "fresh|replay|reuse", "sig": "valid|forged|missing"},
  "expect": {"outcome": "deny", "reason": "..."},
  "ground_truth": "engine-decision"   // v2 decisions are the ground truth
                                     // only for enforcement-layer tests
}
```
`expect.outcome` ∈ allow | deny | escalate | reject(schema).

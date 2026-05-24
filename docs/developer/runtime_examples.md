# Runtime Examples

This document shows how to use the Ovara Runtime gateway to protect actions,
inspect decisions, and work with the trust and shield layers.

## Running the Gateway

```bash
cd runtime/gateway
go run cmd/server/main.go
```

The gateway listens on port 8080 by default. Set `OVARA_CONFIG` to change config path.

## Health Checks

```bash
curl http://localhost:8080/health
# {"status":"ok"}

curl http://localhost:8080/ready
# {"status":"ready"}
```

## Checking an Action (Runtime Check)

```bash
# Allowed action — benign shell command
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:ls -la",
    "environment": "local",
    "agent_identity": {
      "issuer": "ovara",
      "subject_id": "agent-001"
    }
  }'

# Response (allow)
# {"decision":"allow","decision_id":"dec_abc123...",...}
```

## Risky Shell Actions (Escalate)

```bash
# Dangerous shell patterns escalate to approval
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:curl |sh",
    "environment": "dev",
    "agent_identity": {
      "issuer": "ovara",
      "subject_id": "agent-001"
    }
  }'

# Response
# {"decision":"escalate","requires_approval":true,...,
#  "trust_score":0.45,"trust_level":"medium",
#  "trust_context":{"score":0.45,"level":"medium",
#    "anomaly_signals":[{"code":"risky_shell_pattern","pattern":"curl |sh","severity":"high"}],
...}
```

## Git Force Push (Escalate)

```bash
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "git.force_push",
    "resource": "git:acme/api:refs/heads/main",
    "environment": "dev",
    "agent_identity": {
      "issuer": "ovara",
      "subject_id": "agent-001"
    }
  }'

# Response includes risky_git_pattern anomaly signal
```

## Production Targeting (Higher Risk)

```bash
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "git.pull",
    "resource": "git:acme/prod-repo",
    "environment": "production",
    "agent_identity": {
      "issuer": "ovara",
      "subject_id": "agent-001"
    }
  }'

# Response includes production_target anomaly signal
# trust_score reduced by 0.2
```

## With Capability Lease (Scoped Authority)

```bash
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:pwd",
    "environment": "dev",
    "agent_identity": {
      "issuer": "ovara",
      "subject_id": "agent-001"
    },
    "capability_lease": {
      "lease_id": "cap_xyz",
      "issuer": "admin",
      "subject": "agent-001",
      "allowed_actions": ["shell"],
      "resource_scope": "*",
      "expiry": "2026-05-25T00:00:00Z",
      "delegation_depth": 1
    }
  }'

# Note: wildcard scope with shell action triggers weak_lease_scope signal
```

## Creating an Approval

```bash
# After receiving an escalate decision, create an approval
curl -X POST http://localhost:8080/v1/approval/create \
  -H "Content-Type: application/json" \
  -d '{
    "decision_id": "dec_abc123",
    "action_type": "shell",
    "resource": "shell:curl |sh",
    "environment": "dev",
    "agent_id": "agent-001"
  }'

# Response
# {"approval_id":"apr_xyz...","decision_id":"dec_abc123",
#  "action_type":"shell","status":"pending",...}
```

## Approving an Action

```bash
curl -X POST http://localhost:8080/v1/approval/apr_xxx/approve \
  -H "Content-Type: application/json" \
  -d '{"resolved_by": "admin@example.com"}'

# Response
# {"approval_id":"apr_xxx","status":"approved","resolved_by":"admin@example.com",...}
```

## Resuming an Approved Action

```bash
curl -X POST http://localhost:8080/v1/approval/apr_xxx/resume
# Response: {"approved":true,"approval_id":"apr_xxx","decision_id":"dec_abc123",
#            "action_type":"shell","resource":"shell:curl |sh"}
```

## Inspecting Receipts

```bash
# List all receipts
curl http://localhost:8080/v1/receipts

# Get specific receipt
curl http://localhost:8080/v1/receipts/rcpt_abc123

# List receipts by decision
curl http://localhost:8080/v1/receipts/decision/dec_abc123
```

## Trust Context Inspection

```bash
# Get trust context for agent
curl "http://localhost:8080/v1/trust/context?agent_id=agent-001"

# Response
# {"agent_id":"agent-001","restricted":false,"risk_count":2,
#  "last_decision":"escalate","last_decision_at":"2026-05-24T12:00:00Z"}
```

## Shield Status Inspection

```bash
# Get all restricted agents
curl http://localhost:8080/v1/shield/status

# Response
# {"restricted_agents":[{"agent_id":"agent-002","restricted":true,
#   "reason":"manual_restriction","since":"2026-05-24T12:00:00Z"}],"count":1}

# Get specific agent shield status
curl http://localhost:8080/v1/shield/status/agent-002
# {"agent_id":"agent-002","restricted":true,"risk_count":0,
#  "last_decision":"","last_decision_at":"0001-01-01T00:00:00Z"}
```

## Restricting an Agent

```bash
# Manually restrict an agent (e.g., after suspicious behavior)
curl -X POST http://localhost:8080/v1/shield/restrict/agent-003 \
  -H "Content-Type: application/json" \
  -d '{"reason": "suspicious shell patterns detected"}'

# Response: {"agent_id":"agent-003","restricted":true,"reason":"suspicious shell..."}
```

## Unrestricting an Agent

```bash
curl -X POST http://localhost:8080/v1/shield/unrestrict/agent-003
# Response: {"agent_id":"agent-003","restricted":false}
```

## Decision Lookup

```bash
# Look up a specific decision by ID
curl http://localhost:8080/v1/runtime/decision/dec_abc123

# Response (if found in decision cache)
# {"decision_id":"dec_abc123","decision":"escalate",
#  "trust_score":0.45,"trust_level":"medium",
#  "trust_context":{...},...}
```

## Agent Decision History

```bash
# Get receipts for a specific agent
curl http://localhost:8080/v1/runtime/agent/agent-001/recent

# Response
# {"agent_id":"agent-001","receipts":[...],"count":5}
```

## Gateway Status Summary

```bash
# Get gateway status with decision cache and receipt stats
curl http://localhost:8080/v1/runtime/status

# Response
# {"gateway_id":"gw_12345","gateway_name":"local-gateway",
#  "gateway_version":"0.7.0","enrollment_status":"local",
#  "decision_cache_count":150,"decision_cache_max":10000,
#  "receipt_count":42}
```

## Auto-Restriction Behavior

When an agent accumulates 3 or more risk events (deny or escalate decisions) within the decision cache window, the gateway automatically restricts that agent:

```bash
# After 3+ risky decisions, agent is auto-restricted
# Subsequent requests from that agent will:
# - Have decision changed to escalate if was allow
# - Include reason_codes containing "containment_active"
# - Trust score will be reduced by 0.4

# Example: Third risky decision triggers auto-restriction
curl -X POST http://localhost:8080/v1/runtime/check ... # first - no restriction
curl -X POST http://localhost:8080/v1/runtime/check ... # second - no restriction
curl -X POST http://localhost:8080/v1/runtime/check ... # third - agent becomes restricted
```

The auto-restriction threshold is 3 by default. Once restricted, the agent must be manually unrestricted via:
```bash
curl -X POST http://localhost:8080/v1/shield/unrestrict/agent-001
```

## Policy Source Model

The gateway uses a `PolicySource` interface to load policy rules. Local implementations available:
- **InMemorySource**: Uses default rules (shell, github actions escalate)
- **LocalFileSource**: Loads rules from a local JSON file

Future versions can implement remote policy sources for distributed policy distribution.

## Local-Only Limitations (v1)

- **In-memory state**: Shield restrictions, risk counts, and receipts reset on server restart
- **No automatic re-execution**: Approved actions are not automatically re-run — clients must retry
- **No cryptographic verification**: Signatures are placeholder format (`sig_v1_local:...`)
- **No persistent storage**: All stores are in-memory; configure external storage for production
- **No distributed enforcement**: Shield state is local to one gateway instance
- **No policy distribution**: Policy is loaded from local config file; no remote distribution

## Decision Flow Summary

```
Request → Validate → Identity Check → Capability Check →
  Policy Evaluation → Trust Evaluation → Decision

Trust Evaluation adds:
  - Shell pattern signals (dangerous commands)
  - Git pattern signals (force push, branch deletion)
  - Production targeting signal
  - Weak scope signal (wildcard + shell)
  - Delegation depth signal (>3)
  - Restriction/containment signal
  - Repeated risk signal (risk count >= 3)
```

## Trust Score Mapping

| Score Range | Trust Level | Shield Active |
|-------------|-------------|---------------|
| 0.8 - 1.0   | high        | no            |
| 0.5 - 0.8   | medium      | no            |
| 0.0 - 0.5   | low         | yes (<0.6)    |
| 0.0         | none        | yes           |
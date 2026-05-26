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
#  "gateway_version":"0.9.0","enrollment_state":"local",
#  "last_seen_at":"...","last_seen_age_secs":5.2,
#  "pending_approval_count":0,"shield_restricted_agents":0,
#  "decision_cache_count":150,"decision_cache_max":10000,
#  "receipt_count":42}
```

## Runtime Metrics

```bash
# Get runtime metrics (decision counts, latency, heartbeat, policy reload status)
curl http://localhost:8080/v1/runtime/metrics

# Response
# {"decision_counts":{"allow":5,"escalate":3,"deny":2},
#  "action_counts":{"shell":6,"git.push":2,"github.merge":2},
#  "total_decisions":10,"avg_latency_ms":2,"last_latency_ms":1,
#  "last_decision_at":"2026-05-25T12:00:00Z",
#  "approval_counts":3,"heartbeat_count":24,"last_heartbeat_at":"...",
#  "policy_version":"v1","policy_source":"file:./examples/sample_policy.json",
#  "policy_reload_status":"none","policy_reload_last":"...",
#  "policy_reload_err":""}
```

| Field | Description |
|-------|-------------|
| `decision_counts` | Decisions by outcome: allow, deny, escalate |
| `action_counts` | Decisions by action type (shell, git.push, etc.) |
| `total_decisions` | Cumulative decision count since startup |
| `avg_latency_ms` | Average decision latency in milliseconds |
| `last_latency_ms` | Most recent decision latency |
| `last_decision_at` | Timestamp of last decision |
| `approval_counts` | Total approvals created |
| `heartbeat_count` | Total heartbeats sent |
| `last_heartbeat_at` | Timestamp of last heartbeat |
| `policy_version` | Current policy version |
| `policy_source` | `in-memory` or `file:<path>` |
| `policy_reload_status` | `none`, `ok`, or `failed` — state of last reload attempt |
| `policy_reload_last` | Timestamp of last reload attempt |
| `policy_reload_err` | Error message if last reload failed |

**Observing latency and decision volume:**

```bash
# Make a few requests then check metrics
curl -X POST http://localhost:8080/v1/runtime/check -H "Content-Type: application/json" \
  -d '{"action_type":"shell","resource":"shell:pwd","environment":"local","agent_identity":{"issuer":"ovara","subject_id":"test"}}'

curl http://localhost:8080/v1/runtime/metrics | jq '{total_decisions, avg_latency_ms, last_latency_ms, decision_counts}'
```

**Detecting policy reload failures:**

```bash
# Check policy reload status
curl http://localhost:8080/v1/runtime/metrics | jq '{policy_reload_status, policy_reload_last, policy_reload_err}'
# policy_reload_status can be: "none" (no reload attempted yet), "ok" (last reload succeeded), "failed" (last reload failed)
# If policy_reload_status is "failed", check policy_reload_err for the error message
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

### File-Based Policy Loading

LocalFileSource loads policy rules from a JSON file. Configure via:

```bash
OVARA_POLICY_FILE=/path/to/policy.json OVARA_POLICY_REFRESH_INTERVAL=10 go run cmd/server/main.go
```

Or in config:

```yaml
PolicyFile: "/path/to/policy.json"
PolicyRefreshInterval: 10  # seconds
```

#### JSON Schema for Policy Files

```json
{
  "version": "v1",
  "rules": [
    {"action_type": "shell", "environment": "production", "escalate": true},
    {"action_type": "github.merge", "environment": "*", "escalate": true}
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Policy schema version (currently "v1") |
| `rules` | array | List of policy rules |
| `action_type` | string | Action type pattern (e.g., "shell", "github.merge", "*") |
| `environment` | string | Environment pattern ("production", "dev", "*") |
| `escalate` | boolean | If true, matching actions trigger escalate decision |

#### PolicyRefreshInterval Configuration

| Value | Behavior |
|-------|----------|
| `0` | Disabled — no file watching |
| `> 0` | Enabled — server watches file for changes |

When `PolicyRefreshInterval > 0`:
- Server monitors the policy file for modifications
- On file write, policy is reloaded automatically
- No server restart required
- Value is in seconds between check intervals

## Local Enrollment and Heartbeat

The gateway maintains a local enrollment identity that tracks:
- **gateway_id**: stable identifier that persists across restarts
- **gateway_name**: operator-assigned name from config
- **gateway_version**: version string from config
- **enrollment_state**: `local` (not connected to a control plane)
- **environment**: `local`, `dev`, `staging`, or `production`
- **registered_at**: when the gateway first started
- **last_seen_at**: timestamp of the most recent heartbeat

### Enrollment File Location

Enrollment state is stored at:
- Default: `var/data/enrollment.json`
- Configurable via `enrollment_file` in config JSON

The file is created automatically on first start. Directory is created if missing.

### Heartbeat Behavior

The gateway runs a background heartbeat that updates `last_seen_at`:
- Default interval: 30 seconds
- Configurable via `heartbeat_interval_secs` in config
- Each heartbeat persists the enrollment file
- Heartbeat stops gracefully on shutdown (SIGINT/SIGTERM)

### Verifying Enrollment Persistence

```bash
# Start the gateway
cd runtime/gateway && go run cmd/server/main.go

# Check initial enrollment state
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state, last_seen_at}'

# Wait 35 seconds and check last_seen_at has updated
sleep 35
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, last_seen_at, last_seen_age_secs}'

# Restart and verify same gateway_id
# (stop the gateway, start it again, check the id is the same)
pkill -f "go run cmd/server"  # or Ctrl-C
cd runtime/gateway && go run cmd/server/main.go
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state, registered_at}'
```

The `gateway_id` should be identical after a restart if the enrollment file exists.

### Status Endpoint Fields

The `/v1/runtime/status` endpoint returns:

| Field | Description |
|-------|-------------|
| `gateway_id` | Stable gateway identifier (persists across restarts) |
| `gateway_name` | Configured name (default: `local-gateway`) |
| `gateway_version` | Configured version (default: `0.9.0`) |
| `enrollment_state` | Always `local` in v1 (control plane not connected) |
| `environment` | From `OVARA_ENVIRONMENT` env var or config |
| `registered_at` | First start timestamp |
| `last_seen_at` | Last heartbeat timestamp |
| `last_seen_age_secs` | Seconds since last heartbeat |
| `enrollment_healthy` | `true` if enrollment service is healthy |
| `enrollment_file` | Configured enrollment file path |
| `policy_version` | Loaded policy version |
| `policy_source` | `in-memory` or `file:<path>` |
| `hot_reload` | `enabled` or `disabled` |
| `storage_mode` | `in-memory` or `file-backed` |
| `decision_cache_count` | Cached decisions count |
| `decision_cache_max` | Max cache size |
| `receipt_count` | Stored receipts count |
| `pending_approval_count` | Pending approvals (from approval store) |
| `shield_restricted_agents` | Restricted agent count (from shield store) |
| `shield_total_agents` | Total tracked agents (from shield store) |

### What Remains Local-Only in v1

The following are **not** implemented in v1:
- Remote control plane enrollment (always `local` state)
- Gateway identity federation across multiple gateways
- Enrollment file encryption or access control
- Heartbeat sends no external telemetry
- Tags/metadata on enrollment identity are present but unused in decisions

## Control-Plane Readiness Smoke Test

Run this after building or restarting to verify enrollment and heartbeat are working.

### 1. Build and Start

```bash
cd runtime/gateway
go build -o gateway_smoke ./cmd/server/
./gateway_smoke 2>&1 &
sleep 2
```

Expected log output:
```
enrollment heartbeat started (default interval=30s)
gateway_id=gw_XXX enrollment_state=local environment=local
```

### 2. Check Initial Status

```bash
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state, last_seen_at}'
```

Record the `gateway_id`. This should be stable across restarts.

### 3. Wait for Heartbeat Update

```bash
# Wait 35 seconds for at least one heartbeat to fire
sleep 35
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, last_seen_at, last_seen_age_secs}'
```

- `last_seen_age_secs` should be less than 35
- `last_seen_at` should show a recent timestamp

### 4. Verify Persistence (Restart Test)

```bash
# Stop the gateway
pkill -f gateway_smoke
sleep 1

# Restart with same enrollment file
./gateway_smoke 2>&1 &
sleep 2

# Check that gateway_id is the same
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state, registered_at}'
```

If the `gateway_id` is the same as step 2, enrollment persistence is working.

### 5. Check Enrollment File

```bash
# File should exist and contain the gateway identity
cat var/data/enrollment.json | jq '{id, name, version, enrollment_state}'
```

### 6. Verify Full Status Richness

```bash
curl -s http://localhost:8080/v1/runtime/status | jq '{
  gateway_id,
  enrollment_state,
  last_seen_age_secs,
  pending_approval_count,
  shield_restricted_agents,
  shield_total_agents,
  enrollment_file
}'
```

All fields should be present and non-null. `enrollment_healthy` should be `true`.

### 7. Clean Up

```bash
pkill -f gateway_smoke
```

## Local-Only Limitations (v1)

- **Shield restrictions reset on restart**: Risk counts and shield state are in-memory only
- **No automatic re-execution**: Approved actions are not automatically re-run — clients must retry
- **No cryptographic verification**: Signatures are placeholder format (`sig_v1_local:...`)
- **No distributed enforcement**: Shield state is local to one gateway instance
- **No policy distribution**: Policy is loaded from local config file; no remote distribution

## Morning Test Checklist

Use this checklist to verify the gateway is working correctly after a restart.

### 1. Start the Gateway

```bash
cd runtime/gateway
go run cmd/server/main.go
```

Or with file persistence enabled:
```bash
export OVARA_RECEIPTS_FILE="var/data/receipts.json"
export OVARA_APPROVALS_FILE="var/data/approvals.json"
go run cmd/server/main.go
```

### 2. Verify Gateway is Running

```bash
curl http://localhost:8080/health
# Expected: {"status":"ok"}
```

### 3. Check Gateway Status

```bash
curl http://localhost:8080/v1/runtime/status | jq .
# Expected: Shows gateway_id, name, version, cache stats, receipt count
```

### 4. Test a Simple Action

```bash
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "shell",
    "resource": "shell:pwd",
    "environment": "local",
    "agent_identity": {"issuer": "ovara", "subject_id": "agent-test"}
  }' | jq .decision
# Expected: "escalate" (shell actions escalate by default policy)
```

### 5. Verify Receipt Persistence

```bash
curl http://localhost:8080/v1/receipts | jq .count
# Expected: > 0 if actions were processed

# Also check the file exists:
cat var/data/receipts.json | jq .count
```

### 6. Test Trust Context

```bash
curl "http://localhost:8080/v1/trust/context?agent_id=agent-test" | jq .
# Expected: Shows agent's risk_count, last_decision
```

### 7. Test Approval Flow (optional)

```bash
# Create an approval for an escalated action
curl -X POST http://localhost:8080/v1/approval/create \
  -H "Content-Type: application/json" \
  -d '{"decision_id":"dec_test","action_type":"shell","resource":"shell:test","agent_id":"agent-test"}' | jq .

# List pending approvals
curl http://localhost:8080/v1/approval/pending | jq .
```

### 8. Verify Runtime Metrics

```bash
# Check that metrics endpoint is accessible and populated
curl -s http://localhost:8080/v1/runtime/metrics | jq '{total_decisions, heartbeat_count, policy_reload_status}'

# Make a decision and verify it shows up in metrics
curl -X POST http://localhost:8080/v1/runtime/check \
  -H "Content-Type: application/json" \
  -d '{"action_type":"shell","resource":"shell:echo hello","environment":"local","agent_identity":{"issuer":"ovara","subject_id":"metrics-test"}}' | jq .decision

curl -s http://localhost:8080/v1/runtime/metrics | jq '{total_decisions, decision_counts}'
# total_decisions should be 1 higher than before
```

### What to Check If Something Goes Wrong

| Symptom | Check |
|---------|-------|
| Gateway won't start | Check port 8080 is free; check config file syntax |
| Actions always escalate | Default policy; use custom policy file to change |
| No receipts after restart | Verify `var/data/receipts.json` exists |
| Health check fails | Check gateway process is running; check port |

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

## Integrity Checking

The gateway includes an integrity checker that validates consistency across all stores.

```bash
# Run integrity check
curl -s http://localhost:8080/v1/runtime/integrity | jq .
```

Response shape:
```json
{
  "timestamp": "2026-05-26T10:00:00Z",
  "passed": true,
  "issues": [],
  "warnings": [
    {"severity": "low", "category": "event_store", "message": "event store is empty"}
  ],
  "summary": {
    "total_issues": 0,
    "total_warnings": 1,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "store_stats": {
    "events": 0,
    "continuations": 0,
    "executions_total": 0,
    "receipts": 0,
    "approvals_pending": 0
  },
  "version_info": {
    "gateway_id": "gw_123456"
  }
}
```

**Passed field**: `passed: true` means no critical or high severity issues were found. Medium and low severity issues do NOT cause `passed: false`.

**Issue severities**:
- `critical` — data corruption, must fix immediately
- `high` — duplicate IDs, orphaned references, data loss risk
- `medium` — zero timestamps, expired-but-not-marked records
- `low` — empty stores, stuck in escalated state

**What the checker validates**:
- Duplicate event/execution/receipt IDs
- Zero timestamps on records
- Orphaned execution→continuation references
- Orphaned approval IDs on non-approved continuations
- Expired continuations not marked as expired
- Continuation created timestamps

## Admin Repair Operations

The gateway provides admin endpoints for repair and maintenance. These are local-only and unauthenticated — they should only be accessible to operators on the same machine.

```bash
# Reconcile continuations — marks expired records and returns count
curl -X POST http://localhost:8080/v1/admin/reconcile/continuations
# Response: {"action": "reconcile_continuations", "expired": 0, "status": "ok"}

# Reconcile executions — returns execution stats
curl -X POST http://localhost:8080/v1/admin/reconcile/executions
# Response: {"action": "reconcile_executions", "stats": {"total": 0, "succeeded": 0, ...}, "status": "ok"}

# Compact all file-backed stores — rewrites files without stale/tombstoned records
curl -X POST http://localhost:8080/v1/admin/compact
# Response: {"action": "compact", "results": {"continuations": {"status": "compacted"}, ...}, "status": "ok"}

# Sweep continuations — removes expired records (file-backed stores only)
curl -X POST http://localhost:8080/v1/admin/sweep/continuations
# Response: {"action": "sweep_continuations", "removed": 0, "status": "ok"}

# Sweep events — removes tombstoned records (file-backed stores only)
curl -X POST http://localhost:8080/v1/admin/sweep/events
# Response: {"action": "sweep_events", "removed": 0, "status": "ok"}
```

**Important notes**:
- Sweep endpoints only work on file-backed stores; in-memory stores return `{"error": "store does not support sweep"}`
- Compact endpoints return `{"status": "not_file_backed"}` for in-memory stores
- No background sweeper runs automatically — operators must call sweep/compact endpoints manually
- These are local-only endpoints with no authentication

## Snapshot Endpoint

The snapshot endpoint provides a combined view of all stores and metrics:

```bash
curl -s http://localhost:8080/v1/runtime/snapshot | jq .
```

Response shape:
```json
{
  "snapshot_at": "2026-05-26T10:00:00Z",
  "gateway_id": "gw_123456",
  "gateway_name": "local-gateway",
  "enrollment_state": "local",
  "policy_version": "v1-local",
  "decision_cache_count": 0,
  "decision_cache_max": 10000,
  "total_decisions": 42,
  "events": {"count": 0, "storage_mode": "in_memory"},
  "continuations": {"count": 0, "storage_mode": "in_memory", "by_state": {}},
  "executions": {"total": 0, "succeeded": 0, "failed": 0, "running": 0, "storage_mode": "in_memory"},
  "metrics": {
    "decision_counts": {"allow": 30, "deny": 10, "escalate": 2},
    "action_counts": {"shell": 25, "git.push": 5},
    "avg_latency_ms": 1.2
  }
}
```

For file-backed stores, additional fields are included: `retention_days`, `max_records`, `file_path`, `file_size_bytes`.
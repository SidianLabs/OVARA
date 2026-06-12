# Event Model

The Ovara Runtime Gateway emits structured events for every significant
action in the decision pipeline. Events are the foundation of audit
trails, observability, and trust evaluation.

## Event Types

| Event Type | When Emitted | Key Fields |
|------------|--------------|------------|
| `action_requested` | When a `POST /v1/runtime/check` arrives | `agent_id`, `action_type`, `resource` |
| `policy_evaluated` | After policy rules are evaluated | `policy_version`, `matched_rule`, `decision` |
| `identity_verified` | After identity/capability verification | `agent_id`, `lease_id`, `verification_result` |
| `trust_computed` | When trust score is computed for an agent | `agent_id`, `trust_score`, `trust_level` |
| `approval_requested` | When an escalation creates an approval | `approval_id`, `decision_id`, `expires_at` |
| `approval_resolved` | When an approval is approved or denied | `approval_id`, `resolution`, `resolved_by` |
| `action_executed` | When a continuation is executed | `execution_id`, `exit_code`, `duration_ms` |
| `receipt_issued` | When a signed receipt is produced | `receipt_id`, `signature` |
| `anomaly_detected` | When drift/degradation/chain heuristics fire | `anomaly_type`, `severity`, `details` |
| `agent_restricted` | When the shield restricts an agent | `agent_id`, `reason`, `restricted_by` |
| `agent_unrestricted` | When a restriction is cleared | `agent_id`, `unrestricted_by` |

## Event Schema

```json
{
  "event_id": "evt_abc123",
  "event_type": "action_requested",
  "timestamp": "2026-06-01T00:00:00Z",
  "trace_id": "trace_xyz",
  "span_id": "span_001",
  "gateway_id": "gw_prod_001",
  "organization_id": "org_001",
  "agent_id": "agt_001",
  "actor": {
    "type": "agent",
    "id": "agt_001"
  },
  "action": "shell",
  "resource": "shell:git push origin main",
  "environment": "dev",
  "metadata": {
    "client_ip": "10.0.0.1",
    "user_agent": "ovara-sdk/1.0.0"
  }
}
```

## Storage

Events are stored in the
[`runtime/gateway/internal/events`](../../runtime/gateway/internal/events/)
package. The store supports both in-memory and file-backed persistence
(JSONL append-only with file locks). Default retention is 30 days; old
events are purged on startup.

## Querying Events

```bash
# List recent events
curl "http://localhost:8080/v1/runtime/trace?limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Filter by type
curl "http://localhost:8080/v1/runtime/trace?event_type=anomaly_detected&limit=20" \
  -H "Authorization: Bearer $TOKEN"

# Trace by correlation ID
curl "http://localhost:8080/v1/runtime/trace?trace_id=trace_xyz" \
  -H "Authorization: Bearer $TOKEN"
```

## Observability Export

Events can be exported to external observability systems via the
[telemetry pipeline](../../runtime/gateway/internal/observe/):

- **OTLP** — OpenTelemetry-compatible span emission
- **NATS** — subject-based event streaming (`ovara.events`)
- **ClickHouse** — durable analytics storage (5 tables, materialized views, TTL retention)

The pipeline supports multiple exporters simultaneously; events are
fan-out to all enabled exporters.

## Telemetry Schema (ClickHouse)

```sql
CREATE TABLE events (
  event_id      String,
  event_type    LowCardinality(String),
  timestamp     DateTime,
  trace_id      String,
  agent_id      String,
  action        LowCardinality(String),
  resource      String,
  environment   LowCardinality(String),
  decision      LowCardinality(String) DEFAULT '',
  trust_score   Float32 DEFAULT 0,
  metadata      String DEFAULT '{}'
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_type, timestamp)
TTL timestamp + INTERVAL 90 DAY;
```

The schema also includes `event_hourly_agg` (SummingMergeTree),
`decision_traces`, `receipt_archive`, and `trust_scores` tables.

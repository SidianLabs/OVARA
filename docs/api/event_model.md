# Event Model

The Ovara Runtime Gateway emits structured events for every significant
action in the decision pipeline. Events are the foundation of audit
trails, observability, and trust evaluation.

## Event Types

The canonical list lives in
[`runtime/gateway/internal/events/store.go`](../../runtime/gateway/internal/events/store.go).
Current types:

| Event Type | When Emitted |
|------------|--------------|
| `runtime.decision_evaluated` | A `/v1/runtime/check` decision was made |
| `approval.created` | An escalation created an approval request |
| `approval.resolved` | An approval was approved or denied |
| `approval.resumed` | An approved action was resumed |
| `receipt.issued` | A signed receipt was produced |
| `policy.reloaded` | The policy file was reloaded |
| `policy.reload_failed` | A policy reload failed |
| `policy.validated` | `POST /v1/policy/validate` ran |
| `policy.simulated` | `POST /v1/policy/simulate` ran |
| `policy.diff_generated` | `POST /v1/policy/diff` ran |
| `policy.candidate_loaded` | A candidate policy was loaded |
| `policy.promoted` | A candidate policy was promoted |
| `policy.rollback` | Policy rolled back |
| `policy.restored` | Policy restored from history |
| `policy.history_created` | A policy history entry was created |
| `shield.restriction_changed` | The shield restricted/unrestricted an agent |
| `enrollment.heartbeat` | Gateway enrollment heartbeat |
| `continuation.created` | A continuation was created |
| `continuation.queued` | A continuation was queued |
| `continuation.denied` | A continuation was denied |
| `continuation.resumed` | A continuation resumed execution |
| `continuation.expired` | A continuation expired |
| `execution.started` | A continuation execution started |
| `execution.succeeded` | An execution succeeded |
| `execution.failed` | An execution failed |
| `execution.timed_out` | An execution timed out |
| `capability.tracked` | A capability lease was tracked |
| `capability.revoked` | A capability lease was revoked |
| `capability.used` | A capability lease was used |
| `batch.retry.executed` / `batch.retry.skipped` | Bulk retry outcomes |
| `batch.cancel.executed` / `batch.cancel.skipped` | Bulk cancel outcomes |
| `admin.reconcile` / `admin.compact` / `admin.sweep` | Admin maintenance ran |
| `admin.integrity_check` | An integrity check ran |

## Event Schema

```json
{
  "event_id": "evt_abc123",
  "event_type": "runtime.decision_evaluated",
  "event_version": "1.0",
  "timestamp": "2026-06-01T00:00:00Z",
  "seq": 42,
  "gateway_id": "gw_prod_001",
  "agent_id": "agt_001",
  "trace_id": "trace_xyz",
  "decision_id": "dec_001",
  "receipt_id": "rcpt_001",
  "approval_id": "apr_001",
  "continuation_id": "cnt_001",
  "payload": { "...": "type-specific fields" }
}
```

Correlation fields (`decision_id`, `receipt_id`, `approval_id`,
`continuation_id`, `trace_id`) are populated only when relevant to the
event; `payload` carries type-specific data.

## Storage

Events are stored in the
[`runtime/gateway/internal/events`](../../runtime/gateway/internal/events/)
package (in-memory and file-backed JSONL with locks). Default retention
is **7 days** (`events_retention_days`); `events_max_size` /
`events_max_records` bound the store size.

## Querying Events

```bash
# List recent events (supports limit/after pagination and filters
# such as type, agent_id, decision_id, approval_id)
curl "http://localhost:8080/v1/events?type=runtime.decision_evaluated&limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Single event
curl "http://localhost:8080/v1/events/{id}" \
  -H "Authorization: Bearer $TOKEN"

# Correlated trace across the pipeline
curl "http://localhost:8080/v1/runtime/trace?decision_id=dec_001" \
  -H "Authorization: Bearer $TOKEN"

# Export
curl "http://localhost:8080/v1/events/export" \
  -H "Authorization: Bearer $TOKEN"
```

## Observability Export — NOT YET WIRED

The event pipeline described here is the **target** design, not current
behavior. `runtime/gateway/internal/observe/` contains an OTLP span
exporter and a NATS event pipeline, but it is **never instantiated** in
`server.go`; the `otel_*` config fields are parsed and unused, and the
`ConsoleExporter` discards output. The `observability/` Prometheus and
Grafana assets reference `ovara_*` metrics that nothing exports yet.
See [`observability/README.md`](../../observability/README.md) for what
would be required to connect the pipeline (OTLP spans, NATS subjects,
ClickHouse schema under `telemetry/`).

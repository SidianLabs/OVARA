# Event Model

Core event envelope:

```json
{
  "event_id": "evt_123",
  "event_type": "runtime.action_checked",
  "timestamp": "2026-05-24T12:00:00Z",
  "tenant_id": "org_123",
  "agent_id": "agt_123",
  "trace_id": "trc_123",
  "payload": {}
}
```

Design rules:

- immutable events
- versioned payloads
- trace correlation everywhere


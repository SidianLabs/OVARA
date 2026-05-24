# Observability Pipeline

## Design

- OpenTelemetry for instrumentation and wire compatibility
- NATS or Redpanda for event transport
- ClickHouse for high-volume analytical storage
- object storage for durable raw event retention

## Why This Mix

- OpenTelemetry reduces integration friction
- NATS is operationally simple for early event routing
- Redpanda becomes attractive at higher sustained throughput
- ClickHouse is excellent for wide event analytics and trace slicing

## Event Types

- action requested
- policy evaluated
- trust computed
- approval requested
- action executed
- receipt issued
- anomaly detected


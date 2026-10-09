# Observability Pipeline

> **Status: aspirational — not yet wired.** This document describes the
> target architecture. Today the observe pipeline
> (`runtime/gateway/internal/observe/`) is never instantiated in
> `server.go` and the `otel_*` config fields are parsed but unused. The
> earlier dashboard and collector assets were removed because nothing fed
> them (see git history).

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


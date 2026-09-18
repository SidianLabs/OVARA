# ADR 0003: Observability Stack

## Status

Accepted — **implementation pending**: the pipeline code exists under
`runtime/gateway/internal/observe/` but is not instantiated in
`server.go`; no `ovara_*` metrics are exported yet.

## Decision

Standardize on OpenTelemetry-compatible instrumentation, event transport via
NATS or Redpanda, and analytics in ClickHouse.

## Rationale

This mix balances ecosystem compatibility, operational pragmatism, and
high-volume event analysis for autonomous execution telemetry.


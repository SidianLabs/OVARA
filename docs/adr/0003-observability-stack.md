# ADR 0003: Observability Stack

## Status

Accepted

## Decision

Standardize on OpenTelemetry-compatible instrumentation, event transport via
NATS or Redpanda, and analytics in ClickHouse.

## Rationale

This mix balances ecosystem compatibility, operational pragmatism, and
high-volume event analysis for autonomous execution telemetry.


# Observability Assets — Status: NOT YET CONNECTED

> **Aspirational / planned.** The files in this directory are *not wired
> to a running gateway today.*

## What exists

- `prometheus/alerts.yml` — alert rules querying `ovara_*` metrics.
  **No such metrics are currently exported** by the runtime gateway.
- `grafana/*.json` — dashboards querying the same `ovara_*` metrics.
- `../telemetry/` — a NATS → ClickHouse collector and a ClickHouse
  schema that *would* receive gateway events.
- `runtime/gateway/internal/observe/` — an OTLP span exporter and NATS
  event pipeline **that is never instantiated** in
  `runtime/gateway/pkg/server/server.go`. The `otel_*` config fields are
  parsed but read by nothing; `ConsoleExporter` discards its output.

## What is needed to connect it

1. Instantiate the observe pipeline in `server.go` (exporters for OTLP
   spans and NATS events) driven by the existing `otel_enabled` /
   `otel_endpoint` / `otel_sample_rate` config fields.
2. Emit a Prometheus/OTLP metrics endpoint exposing the `ovara_*` series
   referenced by `prometheus/alerts.yml` and the Grafana dashboards
   (or rewrite the queries to whatever metric names are actually
   exported).
3. Point `telemetry/collector` at the NATS subject the gateway actually
   publishes on.

Until then, treat everything in this directory as design intent, not
working telemetry.

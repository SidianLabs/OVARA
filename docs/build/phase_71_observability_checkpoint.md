# Phase 71 — Observability Pipeline Checkpoint

## Branch
`phase-71-observability`

## Goal
Build the observability infrastructure: Go-side telemetry pipeline, OpenTelemetry-compatible span exporter, NATS event streaming adapter, ClickHouse analytics schema, and metrics-to-pipeline bridge.

## Deliverables

### 1. Telemetry Pipeline (`runtime/gateway/internal/observe/pipeline.go`)
- **Exporter interface** — `Export(ctx, *Event) error`, `Close() error`
- **TelemetryPipeline** — fan-out to multiple exporters, Start/Send/SendSync/Shutdown lifecycle
- **ConsoleExporter** — development/debug exporter that marshals events to stdout
- **NoopExporter** — zero-cost no-op for testing

### 2. OTLP Exporter (`runtime/gateway/internal/observe/otlp.go`)
- **OTLPSpan** — traceId, spanId, name, start/end time, attributes, status code
- Span collection with max bounds and ring-buffer overflow protection
- Background flush loop with configurable period
- JSON flush format compatible with OpenTelemetry collector wire format

### 3. NATS Exporter (`runtime/gateway/internal/observe/nats.go`)
- Subject-based routing, configurable URLs, max retry
- Sent/dropped counter tracking
- Defaults: `ovara.events` subject, 3 retries

### 4. Metrics Bridge (`runtime/gateway/internal/observe/bridge.go`)
- **MetricsSnapshotter interface** — decouples metrics from pipeline for testability
- **MetricsSnapshot** — portable snapshot struct (TotalDecisions, AvgLatencyMs, ApprovalCounts, etc.)
- Periodic snapshot emission at configurable interval
- Emits `telemetry.metrics_snapshot` events into the pipeline

### 5. ClickHouse Schema (`telemetry/schema/clickhouse_init.sql`)
- **events** — MergeTree, PM by month, TTL 90 days, ZSTD compression
- **event_hourly_agg** — SummingMergeTree + materialized view for hourly rollups (1 year TTL)
- **decision_traces** — full trace-level analytics, PM by month, 180 day TTL
- **receipt_archive** — durable receipt storage, 365 day TTL
- **trust_scores** — agent trust score time-series, 180 day TTL

### 6. Tests (9 tests)
- Pipeline send, multi-exporter fan-out, shutdown ensures no export
- OTLP span add, retrieval, max span overflow
- NATS config defaults, send, close, stats
- MetricsBridge snapshot emission via mock
- Console and Noop exporter smoke tests

## Validation
- go build ./...: **PASS** (24/24 packages)
- go vet ./...: **PASS**
- go test -race ./...: **PASS** (0 data races)
- go test -race ./identity/...: **PASS**

## Files Changed
- `runtime/gateway/internal/observe/pipeline.go` — new (pipeline + console/noop)
- `runtime/gateway/internal/observe/otlp.go` — new (OTLP span exporter)
- `runtime/gateway/internal/observe/nats.go` — new (NATS exporter)
- `runtime/gateway/internal/observe/bridge.go` — new (metrics bridge)
- `runtime/gateway/internal/observe/pipeline_test.go` — new (9 tests)
- `telemetry/schema/clickhouse_init.sql` — new (5 tables + materialized view)

## Next Phase
Phase 72 — Enterprise Features: SSO integration, compliance exports, audit pipelines

Co-authored-by: CommandCodeBot <noreply@commandcode.ai>

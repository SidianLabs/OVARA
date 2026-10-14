# Observability PRD

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

> **Status: planned — not yet implemented.** The OTLP/NATS/ClickHouse
> pipeline described here is not wired into the runtime gateway today
> (`internal/observe/` is never instantiated in `server.go`). See
> `observability/README.md`.

## Problem

Traditional logs do not model action lineage, dynamic delegation, or evolving
trust in autonomous systems.

## Goals

- trace action flows end to end
- correlate identity, policy, approval, and execution events
- support execution graph views

## Non-Goals

- replacing every existing APM dashboard

## Architecture

- OpenTelemetry ingestion
- event bus
- columnar analytics store
- graph-oriented lineage model

## UX Flows

- operator inspects an action and expands lineage, policy, and trust context

## API Requirements

- event ingestion
- trace query
- execution graph lookup

## Scaling Concerns

- large event volumes
- long retention for regulated workloads

## Threat Models

- telemetry tampering
- missing lineage links

## Adoption Strategy

- ship with local trace viewer and hosted query APIs

## Failure Modes

- partial event loss
- schema drift between integrations

## Rollout Strategy

- local-first, then managed analytics


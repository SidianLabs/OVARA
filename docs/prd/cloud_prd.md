# Cloud PRD

> **Historical snapshot — not the current plan.** Kept for history; it may
> describe code that has since changed or been removed. For what Ovara does
> and promises today, see [docs/GUARANTEES.md](../GUARANTEES.md) and [docs/box.md](../box.md).

## Problem

Customers need managed policy distribution, runtime gateways, and multi-tenant
observability without operating the entire stack themselves.

## Goals

- hosted control plane
- regional runtimes
- tenant isolation
- enterprise-grade reliability

## Non-Goals

- owning customer execution environments in early phases

## Architecture

- global control plane
- regional data plane gateways
- policy distribution service
- managed storage and analytics

## UX Flows

- tenant provisions organization
- deploys runtime gateway
- configures integrations and policies

## API Requirements

- organization management
- policy publishing
- gateway enrollment

## Scaling Concerns

- noisy-neighbor isolation
- cross-region policy consistency

## Threat Models

- tenant breakout
- compromised control plane credential

## Adoption Strategy

- hybrid deployment: self-hosted runtime, hosted control plane

## Failure Modes

- regional outage
- stale policy propagation

## Rollout Strategy

- single-region beta, multi-region GA


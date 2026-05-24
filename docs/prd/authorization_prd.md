# Authorization PRD

## Problem

Static RBAC is too coarse for real-time machine actions with changing context.

## Goals

- combine RBAC, ABAC, ReBAC, and capability checks
- allow trust-aware decisions
- support approval escalation

## Non-Goals

- reproducing all enterprise IAM features in v1

## Architecture

- normalized action model
- policy compiler
- evaluation engine
- decision explanation output

## UX Flows

- author policy
- simulate against sample actions
- enforce at runtime

## API Requirements

- evaluate action
- simulate policy
- fetch explanations

## Scaling Concerns

- fast repeated evaluations
- policy version pinning

## Threat Models

- policy ambiguity
- unsafe defaults
- cached stale decisions

## Adoption Strategy

- ship examples for shell, GitHub, CI/CD, DB, and payments

## Failure Modes

- overly broad allow policy
- denial storms from bad rollout

## Rollout Strategy

- simulation mode then progressive enforcement


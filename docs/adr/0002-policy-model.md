# ADR 0002: Policy Model

## Status

Accepted

## Decision

Adopt a Cedar-like authorization model for core policy evaluation, augmented by
relationship data for delegated authority and optional OPA interoperability.

## Rationale

The hot path needs explicit semantics, bounded complexity, and explainable
decisions. A pure OPA-first approach is too unconstrained for the core runtime.


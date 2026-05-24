# ADR 0001: Core Language Selection

## Status

Accepted

## Decision

Use Rust for security-sensitive hot path components, Go where distributed
systems simplicity and hiring leverage matter, and TypeScript for SDKs, control
plane, CLI, and developer experience.

## Rationale

Rust gives the best long-term foundation for memory safety and low-latency
runtime work. Go accelerates service development for gateways and control-plane
support systems. TypeScript is the fastest route to broad developer adoption.


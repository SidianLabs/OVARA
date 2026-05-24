# Runtime Security Architecture

## Shield Layers

- interception
- sandboxing
- anomaly scoring
- trust degradation
- dynamic containment

## Isolation Options

- container isolation for broad compatibility
- microVMs for higher assurance workloads
- WASM for narrowly bounded execution adapters

Recommendation:

- container sandbox in phase 1
- microVM path for enterprise and high-risk action types


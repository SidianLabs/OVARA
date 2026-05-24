# Delegated Authority Architecture

## Model

Delegated authority is represented as capability leases attached to an explicit
delegation chain.

Each lease includes:

- delegator
- delegatee
- resource scope
- action scope
- expiry
- max delegation depth
- approval constraints

## Rules

- no implicit delegation
- recursive delegation must be capped
- sensitive capabilities require shorter lease durations


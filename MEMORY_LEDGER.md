# Memory Ledger
## Project: Ovara
## Current Phase: 67 (Trust-Aware Security)
## Current Task: 67.1 — Add drift detection

## Completed Tasks
- [x] Phase 65 — V1 Hardening & Cleanup
- [x] Phase 66 — Identity Integration Deepening
- [ ] Phase 67 — Trust-Aware Security

## Active Decisions & Rationale
- Drift detection: track action patterns per agent in sliding time windows
- Trust degradation: exponential decay with configurable half-life, accelerated by repeat offenses
- Trust recovery: clean behavior gradually restores score toward baseline
- Trust-dependent policy rules: extend Rule with MinTrustLevel/MinTrustScore
- Suspicious chaining: detect same-issuer repeat, excessive depth, circular patterns
- Trust state persistence: file-backed store alongside existing persistence patterns

## Open Issues / Gotchas
- Need to avoid making the hot path too expensive — drift computation must be O(1) per check
- Trust state must be thread-safe (already using RWMutex patterns from trust/shield.go)

## Next Immediate Action
- Add drift detection: trust/drift.go with sliding window pattern tracking

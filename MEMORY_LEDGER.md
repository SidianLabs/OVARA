# Memory Ledger
## Project: Ovara
## Current Phase: 66 (Identity Integration Deepening)
## Current Task: 66.1 — Fix payload mismatch + wire full ed25519 verification

## Completed Tasks
- [x] Phase 65 — V1 Hardening & Cleanup
- [ ] Phase 66 — Identity Integration Deepening

## Active Decisions & Rationale
- Critical payload mismatch found: gateway validator omits `issuedAt` from signature payload; identity module includes it
- Gateway validator uses string-based payload; identity module uses same format with identical separator
- Fix: add `IssuedAt` (or timestamp field) to gateway's models.CapabilityLease for compatibility
- Need to add delegation chain hash verification to gateway validator

## Open Issues / Gotchas
- Gateway models.CapabilityLease has no `IssuedAt` field — need to add or use `Expiry` as the reference timestamp
- Identity module's IssuedAt is a read-after-sign field — timestamp is embedded in payload
- The delegation chain in models uses different types than ovara.identity module

## Next Immediate Action
- Fix CapabilityLease signature payload mismatch between ovara.identity and gateway validator
- Add IssuedAt to models.CapabilityLease
- Wire DelegationChain.Verify() into validator
- Add integration tests with real ed25519 keys

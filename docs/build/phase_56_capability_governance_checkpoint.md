# Phase 56 Capability Governance — Checkpoint

**Date**: Tue May 26 2026
**Branch**: `phase-56-capability-governance`
**Parent**: `phase-55-durable-leases` (commits `4f3cf72`, `67d4e04`)
**Objective**: Durable lease history, delegation-chain visibility, and capability governance controls

---

## 1. Repository Verification

- **Current branch**: `phase-56-capability-governance` (freshly created)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **Parent commits reviewed**:
  - `67d4e04` docs(build): finalize phase 55 durable leases checkpoint
  - `4f3cf72` feat(capabilities): add file-backed lease store with persistence, lifecycle history, and delegation visibility

---

## 2. Current State Audit

### What's Implemented (Phase 55 baseline)
- `FileBackedStore` — lease state persisted to JSON, survives restart
- `InMemoryStore` — in-memory fallback
- `HistoryStore` — in-memory only, resets on restart
- `LeaseHistoryEntry` with: LeaseID, Event, Timestamp, GatewayID, Reason, Subject, Issuer
- `GET /v1/capabilities/history` — returns in-memory history (resets on restart)
- `GET /v1/capabilities/{id}` — lease + in-memory history
- `GET /v1/capabilities?subject=X&issuer=Y` — filtering
- `POST /v1/capabilities/revoke` — single lease revoke only
- No delegation chain tracking beyond DelegationDepth field

### What's Missing (Phase 56 goals)
- History resets on restart — needs file-backed persistence
- No bulk revoke (revoke all for a subject)
- No governance filters (by status, issuer)
- Delegation chain visibility is shallow
- Weak correlation between lease events and approvals/executions

---

## 3. Implementation Plan

### Milestone A: Durable Lease History
- [ ] Create `file_history_store.go`: file-backed history store (JSONL append-only)
- [ ] Add `CapabilitiesHistoryFile` to config
- [ ] Wire history store in main.go
- [ ] Add history entries for track/use/revoke that include action/resource metadata
- [ ] Tests for durable history append/load/query

### Milestone B: Delegation-Chain Visibility
- [ ] Enrich `LeaseHistoryEntry` with Action/Resource fields
- [ ] Show delegation depth in lease inspection
- [ ] Add delegation chain info to get endpoint response

### Milestone C: Lease Governance Controls
- [ ] `POST /v1/capabilities/revoke-by-subject` — revoke all active leases for a subject
- [ ] `GET /v1/capabilities?status=active|revoked|all` — filter by status
- [ ] `GET /v1/capabilities?issuer=X` — list by issuer
- [ ] Tests for governance flows

### Milestone D: Correlation and Auditability
- [ ] History entries include action/resource context when available
- [ ] Emit richer events with more context
- [ ] Wire file-backed history store into handler

### Milestone E: Docs and Verification
- [ ] Update checkpoint
- [ ] Run tests
- [ ] Real smoke test: track → use → revoke → restart → verify history survives

---

## 4. Execution Log

_(to be filled as work progresses)_

---

## 5. Files to Create/Modify

### Create
- `runtime/gateway/internal/capabilities/file_history_store.go` — durable history
- `runtime/gateway/internal/capabilities/file_history_store_test.go` — durability tests
- `docs/build/phase_56_capability_governance_checkpoint.md` — this file

### Modify
- `runtime/gateway/internal/capabilities/history.go` — add Action/Resource/ApprovalID fields
- `runtime/gateway/internal/capabilities/store.go` — history entry types
- `runtime/gateway/internal/handlers/capabilities.go` — governance endpoints, status filter
- `runtime/gateway/cmd/server/main.go` — wire file-backed history store
- `runtime/gateway/internal/config/config.go` — CapabilitiesHistoryFile
- `runtime/gateway/internal/events/store.go` — richer event payloads
- `docs/developer/runtime_examples.md` — governance and history docs

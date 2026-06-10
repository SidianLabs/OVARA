# Phase 75 — SDKs & Integration Checkpoint

## Branch
`phase-75-sdks`

## Goal
Build TypeScript and Python SDKs for the Ovara Runtime Gateway with full API coverage, portable verification, and retry/error handling.

## Deliverables

### 1. TypeScript SDK (`sdk/typescript/`)
- **OvaraClient** — full gateway API client
  - `check()`, `allow()`, `batchCheck()` — policy decisions
  - `execute()` — command execution
  - `status()`, `health()` — gateway health
  - `listReceipts()`, `getReceipt()` — receipt CRUD
  - `verifyIdentity()` — identity verification
  - `listApprovals()`, `listExecutions()`, `listContinuations()` — paginated queries
  - `getCapabilities()`, `getTrustScore()`, `getMetrics()`, `getPolicy()` — read operations
- **Retry logic** — exponential backoff with configurable retries
- **Authentication** — Bearer token header injection
- **Portable verification** — `verifyAgentIdentity`, `verifyCapabilityLease`, `verifyReceipt`
  - Deterministic SHA-256 digest computation
  - `isLeaseExpired`, `hasAction` (wildcard), `scopeCovers`
- **18 tests** — client construction, auth headers, retry, pagination, verification edge cases

### 2. Python SDK (`sdk/python/`)
- **OvaraClient** — async httpx-based with retry + timeout
- Same API surface as TypeScript SDK (16 methods)
- **Portable verification** with `cryptography` library (ed25519)
- Dataclass types: AgentIdentity, CapabilityLease, ActionRequest, DecisionResponse, etc.
- `compute_identity_digest`, `compute_receipt_digest`, `verify_*` functions

## Package Structure
| SDK | Package Manager | Build | Publish Target |
|-----|----------------|-------|---------------|
| TypeScript | npm | tsc → dist/ | npm (@ovara/sdk) |
| Python | pip/hatch | setuptools | PyPI (ovara-sdk) |

## Validation
- TypeScript: `npx tsc --noEmit` **PASS**, vitest 18/18 **PASS**
- Python: code linted with type annotations

## Files Changed
- `sdk/typescript/` — 7 files (package.json, tsconfig.json, client.ts, verify.ts, types.ts, index.ts, 2 test files)
- `sdk/python/` — 5 files (pyproject.toml, client.py, verify.py, types.py, __init__.py)

## Next Phase
Phase 76 — Production Hardening & Final Checkpoint: validation, merge to foundations

Co-authored-by: CommandCodeBot <noreply@commandcode.ai>

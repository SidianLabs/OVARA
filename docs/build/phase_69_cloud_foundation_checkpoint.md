# Phase 69 — Cloud Foundation Checkpoint

## Branch
`phase-69-cloud-foundation`

## Goal
Establish the hosted control plane foundation: TypeScript API server, tenant model, gateway enrollment, policy distribution, revocation management, and API key authentication.

## Deliverables

### 1. Control Plane Server (`cloud/control-plane/`)
- **Fastify** HTTP server with CORS, Helmet, rate limiting
- **PostgreSQL** via **Drizzle ORM** with full schema
- **8 API route groups** mounted under `/v1/`:
  - `POST/GET /v1/tenants` — multi-tenant management
  - `POST/GET/PATCH /v1/organizations` — org CRUD
  - `POST /v1/gateways/enroll` — gateway enrollment with expiring tokens
  - `POST /v1/gateways/confirm/:id` — enrollment confirmation
  - `POST /v1/gateways/:id/heartbeat` — health check
  - `POST/GET /v1/policies` — policy CRUD
  - `POST /v1/policies/:id/publish` — publish with gateway distribution
  - `POST/GET /v1/revocations` — lease revocation management
  - `POST/GET /v1/api-keys` — scoped API key management with revocation
- **Auth middleware**: Bearer token auth with SHA-256 hashed keys, scope enforcement
- **Zod validation** on all write endpoints
- **Docker Compose** for local PostgreSQL development

### 2. Database Schema (6 tables)
- `tenants` — multi-tenant isolation root
- `organizations` — per-tenant orgs with settings
- `gateways` — enrolled runtime gateways with public keys and enrollment tokens
- `policies` — versioned policy documents with rules JSON
- `policy_distributions` — delivery tracking per gateway
- `revocations` — lease revocation tracking
- `api_keys` — hashed API keys with scopes and expiry
- `audit_log` — organizational audit trail

### 3. Tests
- `tenants.test.ts` — CRUD + 404 handling
- `gateways.test.ts` — enrollment, confirmation, heartbeat, org-scoped listing
- `policies.test.ts` — create, publish (auto-distribute + targeted), org filtering
- `apiKeys.test.ts` — create, list (no hash leak), revoke

## Validation
- TypeScript strict mode: **PASS** (`npx tsc --noEmit` clean)
- Build: `npm install` succeeded
- Node.js v22.22.3, Fastify v5, Drizzle ORM v0.36

## Architecture Decisions
- **TypeScript for control plane** (per architecture doc stack direction)
- **Fastify** over Express — faster, typed, plugin-based
- **Drizzle ORM** — lightweight, TypeScript-native, no codegen build step
- **SHA-256 API key hashing** using Node.js built-in crypto (no native deps needed)
- **Bearer token auth** pattern: `ovara_<prefix>.<secret>` → SHA-256 hash lookup

## Files Changed
- 19 new files in `cloud/control-plane/`
- Updated `.gitignore` with `node_modules/`

## Next Phase
Phase 70 — Gateway Enrollment Protocol & Policy Sync Service

Co-authored-by: CommandCodeBot <noreply@commandcode.ai>

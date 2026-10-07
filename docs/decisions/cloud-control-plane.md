# Decision: what to do with the cloud control plane and dashboard

Status: **proposed** (2026-10-07). Deciders: maintainers.

## Context

The product is now the single `ovara` binary for developers running coding
agents. It has its own local approval page (`ovara run` → `http://127.0.0.1:9090`).
Next to it sit three TypeScript products that the README already labels
**Experimental, not connected to the gateway**:

| Path | Size (TS/TSX lines) |
|---|---|
| `cloud/control-plane` (Fastify + Drizzle + Postgres) | ~3,100 |
| `apps/admin-dashboard` (Next.js) | ~1,400 |
| `enterprise/sso`, `enterprise/compliance` | ~1,400 |

A review said they don't work with the Go gateway. Each claim was checked
against the code on `product/usable-core` (commit `bcffc8b`):

### They don't interoperate with the gateway

| Claim | Verified? | Evidence |
|---|---|---|
| Control plane rule shape is `{id, action, target, condition?, effect: allow\|deny, priority}` | Yes | `cloud/control-plane/src/schemas/index.ts:42-49` |
| Gateway `PUT /v1/policy` requires `action_type`, `environment`, one of `allow/deny/escalate`, and rejects unknown fields, so every push returns 400 | Yes | route `runtime/gateway/internal/handlers/policy.go:129`; handler `:725-760` calls `policy.ParseStore` → `parseFilePolicyStrict` with `DisallowUnknownFields` (`runtime/gateway/internal/policy/file_store.go:38-39,90,101`); required fields `runtime/gateway/internal/policy/validator.go:208-218` |
| Gateway never builds `enrollment.NewCloudService` / `NewPolicySyncService` | Yes | defined at `runtime/gateway/internal/enrollment/cloud_client.go:90,268`, no non-test caller; the server only builds `enrollment.NewLocalService` (`runtime/gateway/pkg/server/server.go:79`). `control_plane_url` exists only as a status field (`runtime/gateway/internal/config/config.go:196`), not as config that turns anything on |
| Paths also differ | Partly (new) | the gateway's sync client polls `/v1/policies/distributions/{id}` and `/v1/policies/{id}` (`cloud_client.go:284,316`), which exist (`routes/policies.ts:97,122`), but would receive the incompatible rule shape above |

### The control plane can't start from its image

| Claim | Verified? | Evidence |
|---|---|---|
| ESM imports without extensions | Yes | `"type": "module"` (`package.json:5`), `moduleResolution: "bundler"` (`tsconfig.json:5`), `import … from "./routes/tenants"` (`src/server.ts:6-13`). `tsc` emits these unchanged; `node dist/server.js` fails with `ERR_MODULE_NOT_FOUND` |
| `pino-pretty` transport not installed | Yes | `src/server.ts:19-20` uses it whenever `NODE_ENV !== "production"`; it is not in `package.json`, and the `Dockerfile` never sets `NODE_ENV`, so the image takes that branch |
| No migrations | Yes | `drizzle.config.ts` and `db:migrate` script exist, but there is no generated migrations directory and nothing runs migrations at start |
| No way to create the first API key | Yes | the only insert into `api_keys` is `POST /v1/api-keys`, which itself requires an `admin` key (`src/routes/apiKeys.ts:23-33`) |

### Security issues

| Claim | Verified? | Evidence |
|---|---|---|
| Any org-admin key can create tenants | Yes | `src/routes/tenants.ts:20-28`: `requireScope("admin")` only, no platform-level check; the new tenant is not tied to the caller |
| SSRF via admin-set `endpointUrl` + `allowInsecure` | Yes | `src/schemas/index.ts:36-37` accepts any URL; `validateEndpoint` only checks the scheme (`src/distribution/distributor.ts:209-221`, `src/routes/approvals.ts:15-24`), so internal hosts (e.g. `http://169.254.169.254`, `http://localhost:…`) can be targeted; any JSON `approvals` field in the reply is relayed back by `GET /v1/approvals` (`src/routes/approvals.ts:65-78`) |
| One shared `OVARA_GATEWAY_API_KEY` sent to every tenant's gateway | Yes | `src/routes/approvals.ts:12,39`, `src/distribution/distributor.ts:26`. Combined with the SSRF, any tenant admin can capture the key used for all tenants' gateways |
| `resolved_by` taken from the request body | Yes | `src/routes/approvals.ts:109,134` (`body.resolved_by ?? apikey:…`) — the audit identity is caller-chosen |
| Enrollment confirm without proof of possession | Yes | `src/routes/gateways.ts:39-56`: an admin key flips status to `online` and clears the token; the gateway never proves it holds the enrollment token or a key |
| CORS reflects any origin with credentials | Yes | `src/server.ts:26`: `cors, { origin: true, credentials: true }` |
| Dashboard shows mock data silently | Partly | approvals, audit-log, gateways and policies fall back to mock data but show a "demo data — API offline" badge (e.g. `apps/admin-dashboard/src/app/gateways/page.tsx:15,24`). The home page and organizations page are hard-coded and never call the API (`src/app/organizations/page.tsx:6`, `src/components/GatewaysList.tsx:6`, `src/components/RecentDecisions.tsx:4`) |
| Dashboard ships `NEXT_PUBLIC_OVARA_API_KEY` to the browser | Yes | `apps/admin-dashboard/src/lib/api-client.ts:3,140`; `NEXT_PUBLIC_*` is inlined into the client bundle, so an admin key would be public |

Additional finding: the control plane's DB tests skip themselves when Postgres
isn't reachable (`src/__tests__/tenants.test.ts:7-16`) and CI starts no Postgres
service (`.github/workflows/ts-tests.yml`), so CI's "green" for this module
exercises almost none of the route code.

Nothing outside `enterprise/` imports `enterprise/sso` or `enterprise/compliance`;
they are referenced only by the Makefile, `ts-tests.yml`, the README table and
historical docs.

## Option A — remove them

Delete `cloud/control-plane`, `apps/admin-dashboard` and `enterprise/`. Update
`Makefile` (`TS_MODULES`), `.github/workflows/ts-tests.yml` (matrix entries and
the dashboard job), `.github/workflows/docker.yml` (control-plane image),
`.github/workflows/lint.yml` (the control-plane `tslint` job), the README
"What's solid" table and intro, and `CHANGELOG.md`. Historical docs stay as
history; the code stays recoverable from git (tag the last commit that has it).

- **Cost:** ~0.5 engineer-day. Low risk: no Go code or shipped binary depends on it.
- **Gains:** ~5,900 lines and three npm lockfiles gone; CI faster; no
  exploitable code shipped in the repo; the README stops promising a
  cloud product that doesn't exist.
- **Loses:** the scaffolding for a future multi-gateway product. Rebuilding
  later would start from the gateway's real API rather than from this code,
  which is how it should be designed anyway.

## Option B — make the minimal path real

1. **Shared rule format.** The control plane stores and emits gateway rules
   (`action_type`, `environment`, `allow/deny/escalate`, `conditions`), checked
   by a JSON Schema generated from / tested against the Go validator. ~1 day.
2. **Gateway enrolls and syncs** when `control_plane_url` is configured: wire
   `NewCloudService` + `NewPolicySyncService` into `pkg/server`, apply synced
   policy through the same validated path as `PUT /v1/policy`, tests both sides. ~1.5 days.
3. **Startable image:** NodeNext imports with `.js` extensions, drop
   `pino-pretty` in prod, `NODE_ENV=production`, generated Drizzle migrations
   run on start, a `bootstrap` command that creates the first org + admin key
   once. ~1 day.
4. **Security fixes:** platform-admin scope for tenant creation; SSRF guard
   (resolve and block private/link-local/loopback unless an operator-level
   allow-list permits it; no redirects); per-gateway credentials issued at
   enrollment instead of a shared key; `resolved_by` derived from the key;
   confirm requires the gateway to present the enrollment token and a
   public key; CORS allow-list from config; dashboard calls through a
   server-side route so no key reaches the browser, and mock fallbacks removed. ~2 days.
5. **CI with Postgres:** a `services: postgres` job running migrations and the
   route tests un-skipped, plus a gateway↔control-plane integration test. ~1 day.

- **Cost:** ~6–8 engineer-days now, plus ongoing upkeep of a second runtime
  (Node + Postgres) and a multi-tenant security surface that the core product
  doesn't need.
- **Gains:** a working, central place to push policy to many gateways.
- **Risk:** it's a second product. Its value depends on teams running fleets
  of gateways, which is not who the product targets today.

## Recommendation

**A.** The product is a single local binary; the control plane is unused,
can't start, can't talk to the gateway, and carries real multi-tenant
vulnerabilities. Removing it costs half a day and is reversible from git. If
fleet management becomes a goal, design it from the gateway's existing
`PUT /v1/policy` contract then.

## Decision

_Pending — to be filled in when the maintainers choose._

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { organizationRoutes } from "../routes/organizations";
import { apiKeyRoutes } from "../routes/apiKeys";
import { gatewayRoutes } from "../routes/gateways";
import { policyRoutes } from "../routes/policies";
import { db } from "../db/connection";
import { apiKeys, gateways, organizations, policies, policyDistributions, tenants } from "../db/schema";
import { inArray } from "drizzle-orm";

let hasDB = false;

// Two orgs in two different tenants. Org A's key must never see org B's
// resources (and vice versa); routes answer 404 — not 403, not 200 — so a
// foreign key cannot probe for resource existence.
const TENANT_A = "00000000-0000-0000-0000-0000000000a1";
const TENANT_B = "00000000-0000-0000-0000-0000000000b1";
const ORG_A = "00000000-0000-0000-0000-0000000000a2";
const ORG_B = "00000000-0000-0000-0000-0000000000b2";

const AUTH_A = { organizationId: ORG_A, scopes: ["admin", "read", "write"], keyId: "key-a" };
const AUTH_B = { organizationId: ORG_B, scopes: ["admin", "read", "write"], keyId: "key-b" };
const AUTH_A_READONLY = { organizationId: ORG_A, scopes: ["read"], keyId: "key-a-readonly" };

async function checkDB(): Promise<boolean> {
  try {
    await db.execute("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

type AuthStub = { organizationId: string; scopes: string[]; keyId: string } | null;

// auth === null builds an app with no credential stub, so requests exercise
// the real authenticate() path (missing header -> 401).
const buildApp = async (auth: AuthStub) => {
  const app = Fastify();
  app.decorateRequest("auth", null);
  if (auth) {
    app.decorate("authenticate", async (request: any) => {
      request.auth = auth;
    });
    app.addHook("preValidation", async (request) => {
      await (app as any).authenticate(request);
    });
  }
  await app.register(organizationRoutes, { prefix: "/v1/organizations" });
  await app.register(apiKeyRoutes, { prefix: "/v1/api-keys" });
  await app.register(gatewayRoutes, { prefix: "/v1/gateways" });
  await app.register(policyRoutes, { prefix: "/v1/policies" });
  await app.ready();
  return app;
};

describe("Tenant isolation", () => {
  let appA: any = null;
  let appB: any = null;
  let appAnon: any = null;
  let appReadOnly: any = null;
  let gwAId = "";
  let policyAId = "";
  let apiKeyAId = "";

  beforeAll(async () => {
    hasDB = await checkDB();
    if (!hasDB) return;

    appA = await buildApp(AUTH_A);
    appB = await buildApp(AUTH_B);
    appAnon = await buildApp(null);
    appReadOnly = await buildApp(AUTH_A_READONLY);

    await db.insert(tenants).values([
      { id: TENANT_A, name: "iso-tenant-a", displayName: "Isolation Tenant A" },
      { id: TENANT_B, name: "iso-tenant-b", displayName: "Isolation Tenant B" },
    ]).onConflictDoNothing();

    await db.insert(organizations).values([
      { id: ORG_A, tenantId: TENANT_A, name: "iso-org-a", displayName: "Isolation Org A" },
      { id: ORG_B, tenantId: TENANT_B, name: "iso-org-b", displayName: "Isolation Org B" },
    ]).onConflictDoNothing();

    // Seed resources owned by org A through org A's own credentials.
    const gw = await appA.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: { organizationId: ORG_A, name: "iso-gw-a", publicKey: "MCowBQYDK2VwAyEAisoA" },
    });
    gwAId = JSON.parse(gw.payload).id;

    const policy = await appA.inject({
      method: "POST",
      url: "/v1/policies",
      payload: {
        organizationId: ORG_A,
        name: "iso-policy-a",
        rules: [{ id: "r1", action: "shell.execute", target: "sudo", effect: "deny", priority: 100 }],
      },
    });
    policyAId = JSON.parse(policy.payload).id;

    const key = await appA.inject({
      method: "POST",
      url: "/v1/api-keys",
      payload: { organizationId: ORG_A, name: "iso-key-a", scopes: ["read"] },
    });
    apiKeyAId = JSON.parse(key.payload).id;
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        // Scoped cleanup only — other suites share this database.
        await db.delete(policyDistributions).where(inArray(policyDistributions.gatewayId, [gwAId]));
        await db.delete(policies).where(inArray(policies.organizationId, [ORG_A, ORG_B]));
        await db.delete(gateways).where(inArray(gateways.organizationId, [ORG_A, ORG_B]));
        await db.delete(apiKeys).where(inArray(apiKeys.organizationId, [ORG_A, ORG_B]));
        await db.delete(organizations).where(inArray(organizations.id, [ORG_A, ORG_B]));
        await db.delete(tenants).where(inArray(tenants.id, [TENANT_A, TENANT_B]));
      } catch {}
    }
    for (const app of [appA, appB, appAnon, appReadOnly]) {
      if (app) await app.close();
    }
  });

  it("sanity: org A can reach its own resources", async (ctx) => {
    if (!hasDB) return ctx.skip();
    expect((await appA.inject({ method: "GET", url: `/v1/organizations/${ORG_A}` })).statusCode).toBe(200);
    expect((await appA.inject({ method: "GET", url: `/v1/gateways/${gwAId}` })).statusCode).toBe(200);
    expect((await appA.inject({ method: "GET", url: `/v1/policies/${policyAId}` })).statusCode).toBe(200);
  });

  it("returns 404 when org B reads org A's organization", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "GET", url: `/v1/organizations/${ORG_A}` });
    expect(res.statusCode).toBe(404);
  });

  it("returns 404 when org B updates org A's organization", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({
      method: "PATCH",
      url: `/v1/organizations/${ORG_A}`,
      payload: { displayName: "hijacked" },
    });
    expect(res.statusCode).toBe(404);
  });

  it("returns 404 when org B reads org A's gateway", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "GET", url: `/v1/gateways/${gwAId}` });
    expect(res.statusCode).toBe(404);
  });

  it("returns 404 when org B revokes org A's API key", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "POST", url: `/v1/api-keys/${apiKeyAId}/revoke` });
    expect(res.statusCode).toBe(404);
  });

  it("returns 404 when org B reads org A's policy", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "GET", url: `/v1/policies/${policyAId}` });
    expect(res.statusCode).toBe(404);
  });

  it("returns 404 when org B publishes org A's policy", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "POST", url: `/v1/policies/${policyAId}/publish`, payload: {} });
    expect(res.statusCode).toBe(404);
  });

  it("returns 403 when org B lists API keys with org A's organizationId filter", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appB.inject({ method: "GET", url: `/v1/api-keys?organizationId=${ORG_A}` });
    expect(res.statusCode).toBe(403);
  });

  it("org B's list endpoints never leak org A's resources", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const keys = await appB.inject({ method: "GET", url: "/v1/api-keys" });
    expect(JSON.parse(keys.payload).some((k: any) => k.id === apiKeyAId)).toBe(false);
    const gws = await appB.inject({ method: "GET", url: "/v1/gateways" });
    expect(JSON.parse(gws.payload).some((g: any) => g.id === gwAId)).toBe(false);
    const pols = await appB.inject({ method: "GET", url: "/v1/policies" });
    expect(JSON.parse(pols.payload).some((p: any) => p.id === policyAId)).toBe(false);
  });

  it("returns 401 with no credentials", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appAnon.inject({ method: "GET", url: "/v1/organizations" });
    expect(res.statusCode).toBe(401);
    const res2 = await appAnon.inject({ method: "GET", url: `/v1/gateways/${gwAId}` });
    expect(res2.statusCode).toBe(401);
  });

  it("returns 403 when a read-scoped key hits an admin-gated route", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const res = await appReadOnly.inject({
      method: "POST",
      url: "/v1/api-keys",
      payload: { organizationId: ORG_A, name: "escalate", scopes: ["admin"] },
    });
    expect(res.statusCode).toBe(403);
    const res2 = await appReadOnly.inject({ method: "POST", url: `/v1/api-keys/${apiKeyAId}/revoke` });
    expect(res2.statusCode).toBe(403);
  });
});

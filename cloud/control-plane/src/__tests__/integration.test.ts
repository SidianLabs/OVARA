import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";

let hasDB = false;
let app: any = null;
let tenantId = "";
let orgId = "";

async function checkDB(): Promise<boolean> {
  try {
    const { db } = await import("../db/connection");
    await db.execute("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

async function buildTestApp() {
  const { tenantRoutes } = await import("../routes/tenants");
  const { organizationRoutes } = await import("../routes/organizations");
  const { gatewayRoutes } = await import("../routes/gateways");
  const { policyRoutes } = await import("../routes/policies");
  const { apiKeyRoutes } = await import("../routes/apiKeys");

  const a = Fastify({ logger: false });
  a.decorateRequest("auth", null);
  a.decorate("authenticate", async (request: any) => {
    request.auth = {
      organizationId: "00000000-0000-0000-0000-000000000000",
      scopes: ["admin", "read", "write"],
      keyId: "key-superadmin",
    };
  });
  a.addHook("preValidation", async (request: any) => {
    await (a as any).authenticate(request);
  });
  await a.register(tenantRoutes, { prefix: "/v1/tenants" });
  await a.register(organizationRoutes, { prefix: "/v1/organizations" });
  await a.register(gatewayRoutes, { prefix: "/v1/gateways" });
  await a.register(policyRoutes, { prefix: "/v1/policies" });
  await a.register(apiKeyRoutes, { prefix: "/v1/api-keys" });
  await a.ready();
  return a;
}

async function cleanupDB() {
  if (!hasDB) return;
  try {
    const { db } = await import("../db/connection");
    const { apiKeys, policies, gateways, organizations, tenants } = await import("../db/schema");
    await db.delete(apiKeys);
    await db.delete(policies);
    await db.delete(gateways);
    await db.delete(organizations);
    await db.delete(tenants);
  } catch {}
}

describe("Cloud Control Plane Integration", () => {
  beforeAll(async () => {
    hasDB = await checkDB();
    if (hasDB) {
      app = await buildTestApp();
    }
  }, 30000);

  afterAll(async () => {
    await cleanupDB();
    if (app) await app.close();
  });

  it("creates a tenant", async () => {
    if (!hasDB) return;
    const res = await app.inject({
      method: "POST", url: "/v1/tenants",
      payload: { name: "acme-corp", displayName: "Acme Corporation", plan: "enterprise" },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.name).toBe("acme-corp");
    tenantId = body.id;
  });

  it("creates an organization under tenant", async () => {
    if (!hasDB) return;
    const res = await app.inject({
      method: "POST", url: "/v1/organizations",
      payload: { tenantId, name: "acme-engineering", displayName: "Acme Engineering" },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    orgId = body.id;
  });

  it("enrolls a gateway", async () => {
    if (!hasDB) return;
    const res = await app.inject({
      method: "POST", url: "/v1/gateways/enroll",
      payload: { organizationId: orgId, name: "prod-gw-us-east", environment: "production", region: "us-east-1", publicKey: "MCowBQYDK2VwAyEAproductionKey1234567890abcdef" },
    });
    expect(res.statusCode).toBe(201);
  });

  it("creates and publishes a policy", async () => {
    if (!hasDB) return;
    const create = await app.inject({
      method: "POST", url: "/v1/policies",
      payload: {
        organizationId: orgId, name: "production-policy",
        rules: [
          { id: "r1", action: "shell.execute", target: "sudo", effect: "deny", priority: 100 },
          { id: "r2", action: "shell.execute", target: "*", effect: "allow", priority: 0 },
        ],
      },
    });
    expect(create.statusCode).toBe(201);
    const { id } = JSON.parse(create.payload);
    const publish = await app.inject({ method: "POST", url: `/v1/policies/${id}/publish`, payload: {} });
    expect(publish.statusCode).toBe(200);
  });

  it("creates and revokes an API key", async () => {
    if (!hasDB) return;
    const create = await app.inject({
      method: "POST", url: "/v1/api-keys",
      payload: { organizationId: orgId, name: "ci-key", scopes: ["read", "write"] },
    });
    expect(create.statusCode).toBe(201);
    const { id } = JSON.parse(create.payload);
    const revoke = await app.inject({ method: "POST", url: `/v1/api-keys/${id}/revoke` });
    expect(revoke.statusCode).toBe(200);
  });

  it("lists gateways", async () => {
    if (!hasDB) return;
    const res = await app.inject({ method: "GET", url: `/v1/gateways?organizationId=${orgId}` });
    expect(res.statusCode).toBe(200);
  });

  it("lists policies", async () => {
    if (!hasDB) return;
    const res = await app.inject({ method: "GET", url: `/v1/policies?organizationId=${orgId}` });
    expect(res.statusCode).toBe(200);
  });
});

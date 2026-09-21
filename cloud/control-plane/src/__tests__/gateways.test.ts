import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import Fastify from "fastify";
import { gatewayRoutes } from "../routes/gateways";
import { organizationRoutes } from "../routes/organizations";
import { PolicyDistributor } from "../distribution/distributor";
import { db } from "../db/connection";
import { gateways, organizations, policies, policyDistributions } from "../db/schema";

let hasDB = false;

// The mocked API key belongs to this org; all org-scoped resources must use it.
const AUTH_ORG = "00000000-0000-0000-0000-000000000000";

async function checkDB(): Promise<boolean> {
  try {
    await db.execute("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

const buildApp = async () => {
  const app = Fastify();
  app.decorateRequest("auth", null);
  app.decorate("authenticate", async (request: any) => {
    request.auth = { organizationId: AUTH_ORG, scopes: ["admin"], keyId: "key1" };
  });
  app.addHook("preValidation", async (request) => {
    await (app as any).authenticate(request);
  });
  await app.register(organizationRoutes, { prefix: "/v1/organizations" });
  await app.register(gatewayRoutes, { prefix: "/v1/gateways" });
  await app.ready();
  return app;
};

describe("Gateways API", () => {
  let orgId: string;
  let app: any = null;
  const appPromise = buildApp();

  beforeAll(async () => {
    hasDB = await checkDB();
    if (hasDB) {
      app = await appPromise;
      await db.insert(organizations).values({
        id: AUTH_ORG,
        tenantId: "00000000-0000-0000-0000-000000000001",
        name: "gw-test-org",
        displayName: "GW Test Org",
      }).onConflictDoNothing();
      orgId = AUTH_ORG;
    }
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(policyDistributions);
        await db.delete(policies);
        await db.delete(gateways);
        await db.delete(organizations);
      } catch {}
    }
    if (app) await app.close();
  });

  it("enrolls a gateway", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const res = await a.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: {
        organizationId: orgId,
        name: "test-gw-1",
        environment: "production",
        region: "us-west-2",
        publicKey: "MCowBQYDK2VwAyEAabc123",
      },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.status).toBe("enrolling");
    expect(body.enrollmentToken).toMatch(/^ovara_enr_/);
  });

  it("confirms enrollment", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const enroll = await a.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: {
        organizationId: orgId,
        name: "test-gw-2",
        publicKey: "MCowBQYDK2VwAyEAdef456",
      },
    });
    const { id } = JSON.parse(enroll.payload);
    const res = await a.inject({ method: "POST", url: `/v1/gateways/confirm/${id}` });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload).status).toBe("online");
    expect(JSON.parse(res.payload).enrollmentToken).toBeNull();
  });

  it("distributes a policy to a confirmed gateway end-to-end", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const enroll = await a.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: {
        organizationId: orgId,
        name: "test-gw-dist",
        publicKey: "MCowBQYDK2VwAyEAjkl012",
        endpointUrl: "https://test-gw-dist.example.internal:9443",
      },
    });
    const { id } = JSON.parse(enroll.payload);
    const confirm = await a.inject({ method: "POST", url: `/v1/gateways/confirm/${id}` });
    expect(JSON.parse(confirm.payload).status).toBe("online");

    const [policy] = await db.insert(policies).values({
      organizationId: orgId,
      name: "e2e-policy",
      rules: [],
      status: "published",
    }).returning();

    const dist = new PolicyDistributor({ retryBaseDelayMs: 10, maxRetries: 1 });
    vi.spyOn(dist as any, "pushPolicyToGateway").mockResolvedValue(undefined);
    const result = await dist.distributeToGateway(id, {
      id: policy.id,
      organizationId: orgId,
      name: policy.name,
      version: policy.version,
      rules: [],
      status: "published",
    });
    expect(result.status).toBe("delivered");
    vi.restoreAllMocks();
  });

  it("lists gateways by organization", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const res = await a.inject({
      method: "GET",
      url: `/v1/gateways?organizationId=${orgId}`,
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(Array.isArray(body)).toBe(true);
  });

  it("lists organizations created under the caller's tenant", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const create = await a.inject({
      method: "POST",
      url: "/v1/organizations",
      payload: { name: "sibling-org", displayName: "Sibling Org" },
    });
    expect(create.statusCode).toBe(201);
    const created = JSON.parse(create.payload);

    const res = await a.inject({ method: "GET", url: "/v1/organizations" });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.some((o: any) => o.id === created.id)).toBe(true);

    const getOne = await a.inject({ method: "GET", url: `/v1/organizations/${created.id}` });
    expect(getOne.statusCode).toBe(200);
    expect(JSON.parse(getOne.payload).id).toBe(created.id);
  });

  it("records heartbeat", async (ctx) => {
    if (!hasDB) return ctx.skip();
    const a = await appPromise;
    const enroll = await a.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: {
        organizationId: orgId,
        name: "test-gw-hb",
        publicKey: "MCowBQYDK2VwAyEAghi789",
      },
    });
    const { id } = JSON.parse(enroll.payload);
    const res = await a.inject({ method: "POST", url: `/v1/gateways/${id}/heartbeat` });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload).lastHeartbeat).toBeTruthy();
  });
});

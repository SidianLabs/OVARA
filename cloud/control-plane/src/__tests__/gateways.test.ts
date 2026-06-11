import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { gatewayRoutes } from "../routes/gateways";
import { organizationRoutes } from "../routes/organizations";
import { db } from "../db/connection";
import { gateways, organizations } from "../db/schema";

let hasDB = false;

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
    request.auth = { organizationId: "00000000-0000-0000-0000-000000000000", scopes: ["admin"], keyId: "key1" };
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
      const res = await app.inject({
        method: "POST",
        url: "/v1/organizations",
        payload: { tenantId: "00000000-0000-0000-0000-000000000001", name: "gw-test-org", displayName: "GW Test Org" },
      });
      orgId = JSON.parse(res.payload).id;
    }
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(gateways);
        await db.delete(organizations);
      } catch {}
    }
    if (app) await app.close();
  });

  it("enrolls a gateway", async () => {
    if (!hasDB) return;
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

  it("confirms enrollment", async () => {
    if (!hasDB) return;
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
    expect(JSON.parse(res.payload).status).toBe("active");
    expect(JSON.parse(res.payload).enrollmentToken).toBeNull();
  });

  it("lists gateways by organization", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({
      method: "GET",
      url: `/v1/gateways?organizationId=${orgId}`,
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(Array.isArray(body)).toBe(true);
  });

  it("records heartbeat", async () => {
    if (!hasDB) return;
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

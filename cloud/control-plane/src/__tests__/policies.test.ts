import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { policyRoutes } from "../routes/policies";
import { organizationRoutes } from "../routes/organizations";
import { gatewayRoutes } from "../routes/gateways";
import { db } from "../db/connection";
import { policies, policyDistributions, organizations, gateways } from "../db/schema";

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
  await app.register(policyRoutes, { prefix: "/v1/policies" });
  await app.ready();
  return app;
};

describe("Policies API", () => {
  let orgId: string;
  let gwId: string;
  const appPromise = buildApp();

  beforeAll(async () => {
    const app = await appPromise;
    const orgRes = await app.inject({
      method: "POST",
      url: "/v1/organizations",
      payload: { tenantId: "00000000-0000-0000-0000-000000000001", name: "policy-org", displayName: "Policy Org" },
    });
    orgId = JSON.parse(orgRes.payload).id;
    const gwRes = await app.inject({
      method: "POST",
      url: "/v1/gateways/enroll",
      payload: { organizationId: orgId, name: "policy-gw", publicKey: "MCowBQYDK2VwAyEApolicy1" },
    });
    gwId = JSON.parse(gwRes.payload).id;
  });

  afterAll(async () => {
    await db.delete(policyDistributions);
    await db.delete(policies);
    await db.delete(gateways);
    await db.delete(organizations);
  });

  it("creates a policy", async () => {
    const app = await appPromise;
    const res = await app.inject({
      method: "POST",
      url: "/v1/policies",
      payload: {
        organizationId: orgId,
        name: "block-sudo",
        rules: [
          { id: "r1", action: "shell.execute", target: "sudo", effect: "deny", priority: 100 },
          { id: "r2", action: "shell.execute", target: "*", effect: "allow", priority: 0 },
        ],
      },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.status).toBe("draft");
    expect(body.rules).toHaveLength(2);
  });

  it("publishes a policy", async () => {
    const app = await appPromise;
    const create = await app.inject({
      method: "POST",
      url: "/v1/policies",
      payload: {
        organizationId: orgId,
        name: "publish-test",
        rules: [{ id: "r1", action: "git.push", target: "main", effect: "deny", priority: 100 }],
      },
    });
    const { id } = JSON.parse(create.payload);
    const res = await app.inject({
      method: "POST",
      url: `/v1/policies/${id}/publish`,
      payload: {},
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.status).toBe("published");
    expect(body.distributedTo).toBeGreaterThan(0);
  });

  it("publishes to specific gateways", async () => {
    const app = await appPromise;
    const create = await app.inject({
      method: "POST",
      url: "/v1/policies",
      payload: {
        organizationId: orgId,
        name: "targeted-publish",
        rules: [{ id: "r1", action: "shell.execute", target: "rm", effect: "deny", priority: 100 }],
      },
    });
    const { id } = JSON.parse(create.payload);
    const res = await app.inject({
      method: "POST",
      url: `/v1/policies/${id}/publish`,
      payload: { gatewayIds: [gwId] },
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload).distributedTo).toBe(1);
  });

  it("lists policies for org", async () => {
    const app = await appPromise;
    const res = await app.inject({ method: "GET", url: `/v1/policies?organizationId=${orgId}` });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(JSON.parse(res.payload))).toBe(true);
  });
});

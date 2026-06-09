import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { tenantRoutes } from "../routes/tenants";
import { db } from "../db/connection";
import { tenants } from "../db/schema";

const buildApp = async () => {
  const app = Fastify();
  app.decorateRequest("auth", null);
  app.decorate("authenticate", async (request: any) => {
    request.auth = { organizationId: "00000000-0000-0000-0000-000000000000", scopes: ["admin"], keyId: "key1" };
  });
  app.addHook("preValidation", async (request) => {
    await (app as any).authenticate(request);
  });
  await app.register(tenantRoutes, { prefix: "/v1/tenants" });
  await app.ready();
  return app;
};

describe("Tenants API", () => {
  const appPromise = buildApp();

  afterAll(async () => {
    await db.delete(tenants);
  });

  it("creates a tenant", async () => {
    const app = await appPromise;
    const res = await app.inject({
      method: "POST",
      url: "/v1/tenants",
      payload: { name: "acme-corp", displayName: "Acme Corporation", plan: "pro" },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.name).toBe("acme-corp");
    expect(body.plan).toBe("pro");
  });

  it("lists tenants", async () => {
    const app = await appPromise;
    const res = await app.inject({ method: "GET", url: "/v1/tenants" });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(Array.isArray(body)).toBe(true);
  });

  it("gets tenant by id", async () => {
    const app = await appPromise;
    const create = await app.inject({
      method: "POST",
      url: "/v1/tenants",
      payload: { name: "get-test", displayName: "Get Test" },
    });
    const { id } = JSON.parse(create.payload);
    const res = await app.inject({ method: "GET", url: `/v1/tenants/${id}` });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload).name).toBe("get-test");
  });

  it("returns 404 for missing tenant", async () => {
    const app = await appPromise;
    const res = await app.inject({
      method: "GET",
      url: "/v1/tenants/00000000-0000-0000-0000-000000000099",
    });
    expect(res.statusCode).toBe(404);
  });
});

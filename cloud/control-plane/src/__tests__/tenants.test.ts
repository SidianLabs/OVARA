import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { tenantRoutes } from "../routes/tenants";
import { db } from "../db/connection";
import { tenants } from "../db/schema";

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
  await app.register(tenantRoutes, { prefix: "/v1/tenants" });
  await app.ready();
  return app;
};

describe("Tenants API", () => {
  let app: any = null;
  const appPromise = buildApp();

  beforeAll(async () => {
    hasDB = await checkDB();
    if (hasDB) {
      app = await appPromise;
    }
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(tenants);
      } catch {}
    }
    if (app) await app.close();
  });

  it("creates a tenant", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({
      method: "POST",
      url: "/v1/tenants",
      payload: { name: "acme-corp", displayName: "Acme Corporation", plan: "enterprise" },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.name).toBe("acme-corp");
  });

  it("lists tenants", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({ method: "GET", url: "/v1/tenants" });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(JSON.parse(res.payload))).toBe(true);
  });

  it("returns 404 for missing tenant", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({
      method: "GET",
      url: "/v1/tenants/00000000-0000-0000-0000-000000000099",
    });
    expect(res.statusCode).toBe(404);
  });
});

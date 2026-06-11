import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { apiKeyRoutes } from "../routes/apiKeys";
import { organizationRoutes } from "../routes/organizations";
import { db } from "../db/connection";
import { apiKeys, organizations } from "../db/schema";

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
  await app.register(apiKeyRoutes, { prefix: "/v1/api-keys" });
  await app.ready();
  return app;
};

describe("API Keys API", () => {
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
        payload: { tenantId: "00000000-0000-0000-0000-000000000001", name: "key-org", displayName: "Key Org" },
      });
      orgId = JSON.parse(res.payload).id;
    }
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(apiKeys);
        await db.delete(organizations);
      } catch {}
    }
    if (app) await app.close();
  });

  it("creates an API key", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({
      method: "POST",
      url: "/v1/api-keys",
      payload: { organizationId: orgId, name: "ci-key", scopes: ["read", "write"] },
    });
    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.payload);
    expect(body.key).toMatch(/^ovara_/);
    expect(body.prefix).toBeTruthy();
    expect(body.scopes).toEqual(["read", "write"]);
  });

  it("lists keys for org (without hash)", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const res = await a.inject({ method: "GET", url: `/v1/api-keys?organizationId=${orgId}` });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(Array.isArray(body)).toBe(true);
    body.forEach((k: any) => {
      expect(k.keyHash).toBeUndefined();
      expect(k.key).toBeUndefined();
    });
  });

  it("revokes an API key", async () => {
    if (!hasDB) return;
    const a = await appPromise;
    const create = await a.inject({
      method: "POST",
      url: "/v1/api-keys",
      payload: { organizationId: orgId, name: "temp-key", scopes: ["read"] },
    });
    const { id } = JSON.parse(create.payload);
    const res = await a.inject({ method: "POST", url: `/v1/api-keys/${id}/revoke` });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload).revokedAt).toBeTruthy();
  });
});

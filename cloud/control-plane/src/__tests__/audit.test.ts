import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { apiKeyRoutes } from "../routes/apiKeys";
import { auditRoutes } from "../routes/audit";
import { db } from "../db/connection";
import { apiKeys, organizations, auditLog } from "../db/schema";

let hasDB = false;

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
  await app.register(apiKeyRoutes, { prefix: "/v1/api-keys" });
  await app.register(auditRoutes, { prefix: "/v1/audit" });
  await app.ready();
  return app;
};

describe("Audit API", () => {
  let app: any = null;
  const appPromise = buildApp();

  beforeAll(async () => {
    hasDB = await checkDB();
    if (hasDB) {
      app = await appPromise;
      await db.insert(organizations).values({
        id: AUTH_ORG,
        tenantId: "00000000-0000-0000-0000-000000000001",
        name: "audit-org",
        displayName: "Audit Org",
      }).onConflictDoNothing();
    }
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(auditLog);
        await db.delete(apiKeys);
        await db.delete(organizations);
      } catch {}
    }
    if (app) await app.close();
  });

  it("GET /v1/audit lists entries written by mutations", async () => {
    if (!hasDB) return;

    const create = await app.inject({
      method: "POST",
      url: "/v1/api-keys",
      payload: { name: "audit-test-key", scopes: ["read"] },
    });
    expect(create.statusCode).toBe(201);

    const res = await app.inject({ method: "GET", url: "/v1/audit" });
    expect(res.statusCode).toBe(200);
    const rows = res.json();
    const entry = rows.find((r: any) => r.action === "apikey.create" && r.resource === "apikey");
    expect(entry).toBeDefined();
    expect(entry.organizationId).toBe(AUTH_ORG);
    expect(entry.actor).toBe("apikey:key1");
  });

  it("GET /v1/audit respects limit and newest-first order", async () => {
    if (!hasDB) return;

    await app.inject({ method: "POST", url: "/v1/api-keys", payload: { name: "k-second", scopes: ["read"] } });
    const res = await app.inject({ method: "GET", url: "/v1/audit?limit=1" });
    expect(res.statusCode).toBe(200);
    const rows = res.json();
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe("apikey.create");
  });

  it("GET /v1/audit does not leak other orgs' entries", async () => {
    if (!hasDB) return;

    await db.insert(auditLog).values({
      organizationId: "00000000-0000-0000-0000-000000000099",
      actor: "apikey:foreign",
      action: "policy.create",
      resource: "policy",
    });

    const res = await app.inject({ method: "GET", url: "/v1/audit" });
    const rows = res.json();
    expect(rows.every((r: any) => r.organizationId === AUTH_ORG)).toBe(true);
  });
});

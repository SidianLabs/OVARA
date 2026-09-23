import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import { createServer, Server } from "http";
import { AddressInfo } from "net";
import { approvalRoutes } from "../routes/approvals";
import { db } from "../db/connection";
import { apiKeys, organizations, gateways, auditLog } from "../db/schema";

let hasDB = false;

const AUTH_ORG = "00000000-0000-0000-0000-000000000010";
const OTHER_ORG = "00000000-0000-0000-0000-000000000011";

async function checkDB(): Promise<boolean> {
  try {
    await db.execute("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

// Fake gateway: serves the gateway approval surface over http on
// loopback (the gateway row sets allowInsecure for this test path).
async function startFakeGateway(): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/v1/approvals" && req.method === "GET") {
      res.end(JSON.stringify({
        approvals: [
          { approval_id: "ap_1", decision_id: "dec_1", action_type: "shell.exec", resource: "shell:x", environment: "local", status: "pending", created_at: "2026-01-01T00:00:00Z", agent_id: "agent-a" },
        ],
        count: 1,
      }));
      return;
    }
    if (req.url === "/v1/approval/ap_1/approve" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const parsed = JSON.parse(body || "{}");
        res.end(JSON.stringify({ approval_id: "ap_1", status: "approved", resolved_by: parsed.resolved_by }));
      });
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return { server, url: `http://127.0.0.1:${port}` };
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
  await app.register(approvalRoutes, { prefix: "/v1/approvals" });
  await app.ready();
  return app;
};

describe("Approvals proxy", () => {
  let app: any = null;
  let fakeGw: { server: Server; url: string } | null = null;
  let gwId = "";
  const appPromise = buildApp();

  beforeAll(async () => {
    hasDB = await checkDB();
    if (!hasDB) return;
    app = await appPromise;
    fakeGw = await startFakeGateway();
    await db.insert(organizations).values({
      id: AUTH_ORG,
      tenantId: "00000000-0000-0000-0000-000000000012",
      name: "approvals-org",
      displayName: "Approvals Org",
    }).onConflictDoNothing();
    const [gw] = await db.insert(gateways).values({
      organizationId: AUTH_ORG,
      name: "fake-gw",
      endpointUrl: fakeGw!.url,
      allowInsecure: true,
      publicKey: "pk",
    }).returning();
    gwId = gw.id;
  }, 30000);

  afterAll(async () => {
    if (hasDB) {
      try {
        await db.delete(auditLog);
        await db.delete(gateways);
        await db.delete(apiKeys);
        await db.delete(organizations);
      } catch {}
    }
    if (app) await app.close();
    if (fakeGw) await new Promise((r) => fakeGw!.server.close(r));
  });

  it("GET /v1/approvals aggregates the gateway's approval list", async () => {
    if (!hasDB) return;
    const res = await app.inject({ method: "GET", url: "/v1/approvals" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(1);
    expect(body.gateways[0].gatewayId).toBe(gwId);
    expect(body.gateways[0].approvals[0].approval_id).toBe("ap_1");
    expect(body.gateways[0].error).toBeNull();
  });

  it("POST approve proxies the resolution and audits it", async () => {
    if (!hasDB) return;
    const res = await app.inject({
      method: "POST",
      url: `/v1/approvals/${gwId}/ap_1/approve`,
      payload: {},
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe("approved");
    expect(body.resolved_by).toBe("apikey:key1");

    const rows = await db.select().from(auditLog);
    const entry = rows.find((r: any) => r.action === "approval.approve" && r.resourceId === "ap_1");
    expect(entry).toBeTruthy();
  });

  it("approve against a gateway in another org is 404", async () => {
    if (!hasDB) return;
    const [other] = await db.insert(organizations).values({
      id: OTHER_ORG,
      tenantId: "00000000-0000-0000-0000-000000000013",
      name: "other-org",
      displayName: "Other Org",
    }).onConflictDoNothing().returning();
    const [otherGw] = await db.insert(gateways).values({
      organizationId: other.id,
      name: "other-gw",
      endpointUrl: fakeGw!.url,
      allowInsecure: true,
      publicKey: "pk",
    }).returning();
    const res = await app.inject({
      method: "POST",
      url: `/v1/approvals/${otherGw.id}/ap_1/approve`,
      payload: {},
    });
    expect(res.statusCode).toBe(404);
    await db.delete(gateways);
    await db.delete(organizations);
  });
});

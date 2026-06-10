import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { PolicyDistributor } from "../distributor";
import type { Policy } from "../types";

let hasDB = false;
let db: any;
let schema: any;

const testOrgId = "00000000-0000-0000-0000-000000000099";

async function checkDB(): Promise<boolean> {
  try {
    const connection = await import("../../db/connection");
    await connection.db.execute("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

const makePolicy = (overrides?: Partial<Policy>): Policy => ({
  id: "00000000-0000-0000-0000-000000000100",
  organizationId: testOrgId,
  name: "test-policy",
  version: 1,
  rules: [
    { id: "r1", action: "shell.execute", target: "sudo", effect: "deny", priority: 100 },
  ],
  status: "published",
  ...overrides,
});

describe("PolicyDistributor", () => {
  let gw1Id: string;
  let gw2Id: string;
  let dist: PolicyDistributor;

  beforeAll(async () => {
    hasDB = await checkDB();
    if (!hasDB) return;

    const connection = await import("../../db/connection");
    db = connection.db;
    schema = await import("../../db/schema");
    const { eq } = await import("drizzle-orm");

    await db.insert(schema.organizations).values({
      id: testOrgId,
      tenantId: "00000000-0000-0000-0000-000000000001",
      name: "dist-test-org",
      displayName: "Dist Test Org",
    }).onConflictDoNothing();

    const [gw1] = await db.insert(schema.gateways).values({
      organizationId: testOrgId,
      name: "dist-gw-1",
      publicKey: "MCowBQYDK2VwAyEA1",
      status: "online",
    }).returning();
    gw1Id = gw1.id;

    const [gw2] = await db.insert(schema.gateways).values({
      organizationId: testOrgId,
      name: "dist-gw-2",
      publicKey: "MCowBQYDK2VwAyEA2",
      status: "online",
    }).returning();
    gw2Id = gw2.id;

    dist = new PolicyDistributor({ retryBaseDelayMs: 10, maxRetries: 2 });
  }, 30000);

  afterAll(async () => {
    if (!hasDB || !db) return;
    const { eq } = await import("drizzle-orm");
    await db.delete(schema.policyDistributions);
    await db.delete(schema.gateways).where(eq(schema.gateways.organizationId, testOrgId));
    await db.delete(schema.policies).where(eq(schema.policies.organizationId, testOrgId));
    await db.delete(schema.organizations).where(eq(schema.organizations.id, testOrgId));
  });

  it("distributes policy to multiple gateways", async () => {
    if (!hasDB) return;
    const policy = makePolicy();
    const results = await dist.distributePolicy(testOrgId, policy);

    expect(results).toHaveLength(2);
    expect(results.every((r) => r.gatewayId === gw1Id || r.gatewayId === gw2Id)).toBe(true);
  });

  it("distributes to a specific gateway", async () => {
    if (!hasDB) return;
    const policy = makePolicy({ id: "00000000-0000-0000-0000-000000000101" });
    const result = await dist.distributeToGateway(gw1Id, policy);

    expect(result.gatewayId).toBe(gw1Id);
    expect(result.status).toBe("delivered");
  });

  it("handles failed gateway gracefully", async () => {
    if (!hasDB) return;
    const [offlineGw] = await db.insert(schema.gateways).values({
      organizationId: testOrgId,
      name: "offline-gw",
      publicKey: "MCowBQYDK2VwAyEA3",
      status: "enrolling",
    }).returning();

    const policy = makePolicy({ id: "00000000-0000-0000-0000-000000000102" });
    const result = await dist.distributeToGateway(offlineGw.id, policy);

    expect(result.status).toBe("failed");
    expect(result.error).toContain("enrolling");
  });

  it("retries failed distributions", async () => {
    if (!hasDB) return;
    const [failedGw] = await db.insert(schema.gateways).values({
      organizationId: testOrgId,
      name: "fail-gw",
      publicKey: "MCowBQYDK2VwAyEA4",
      status: "online",
    }).returning();

    vi.spyOn(dist as any, "pushPolicyToGateway")
      .mockRejectedValueOnce(new Error("Connection refused"))
      .mockResolvedValueOnce(undefined);

    const policy = makePolicy({ id: "00000000-0000-0000-0000-000000000103" });
    const result = await dist.distributeToGateway(failedGw.id, policy);

    expect(result.status).toBe("delivered");
    vi.restoreAllMocks();
  });

  it("records distribution history", async () => {
    if (!hasDB) return;
    const policy = makePolicy({ id: "00000000-0000-0000-0000-000000000104" });
    await dist.distributeToGateway(gw1Id, policy);

    const history = dist.getHistory();
    expect(history.length).toBeGreaterThan(0);
    expect(history.some((h) => h.gatewayId === gw1Id)).toBe(true);
  });

  it("tracks distribution status", async () => {
    if (!hasDB) return;
    const status = await dist.getDistributionStatus(testOrgId);

    expect(status).toHaveProperty("total");
    expect(status).toHaveProperty("delivered");
    expect(status).toHaveProperty("pending");
    expect(status).toHaveProperty("failed");
    expect(status.total).toBeGreaterThanOrEqual(0);
  });

  it("returns failed for non-existent gateway", async () => {
    if (!hasDB) return;
    const policy = makePolicy({ id: "00000000-0000-0000-0000-000000000105" });
    const result = await dist.distributeToGateway(
      "00000000-0000-0000-0000-999999999999",
      policy,
    );

    expect(result.status).toBe("failed");
    expect(result.error).toContain("not found");
  });
});

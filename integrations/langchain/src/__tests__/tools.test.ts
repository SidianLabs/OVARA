import { describe, it, expect, vi, beforeEach } from "vitest";
import { OvaraCheckTool, OvaraStatusTool, OvaraReceiptsTool } from "../tools";

globalThis.fetch = vi.fn().mockResolvedValue({
  ok: true,
  json: () => Promise.resolve({}),
});

describe("OvaraCheckTool", () => {
  it("has correct name and description", () => {
    expect(OvaraCheckTool.name).toBe("ovara_check_action");
    expect(OvaraCheckTool.description).toContain("Ovara runtime trust policy");
  });

  it("schema has required fields", () => {
    expect(OvaraCheckTool.schema.type).toBe("object");
    const props = OvaraCheckTool.schema.properties as any;
    expect(props.action.type).toBe("string");
    expect(props.resource.type).toBe("string");
  });

  it("_call returns JSON string", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ decision: "allow" }),
    });
    const result = await OvaraCheckTool._call({ action: "shell.execute", resource: "ls" });
    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe("allow");
  });
});

describe("OvaraStatusTool", () => {
  it("has correct name", () => {
    expect(OvaraStatusTool.name).toBe("ovara_gateway_status");
  });

  it("_call returns JSON string", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ gatewayId: "gw-test", isHealthy: true }),
    });
    const result = await OvaraStatusTool._call({});
    const parsed = JSON.parse(result);
    expect(parsed.gatewayId).toBe("gw-test");
  });
});

describe("OvaraReceiptsTool", () => {
  it("_call returns JSON array", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([{ receiptId: "r1" }]),
    });
    const result = await OvaraReceiptsTool._call({ limit: 10, offset: 0 });
    const parsed = JSON.parse(result);
    expect(Array.isArray(parsed)).toBe(true);
  });
});

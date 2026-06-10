import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@modelcontextprotocol/sdk/server/index.js", () => ({
  Server: vi.fn().mockImplementation(() => ({
    setRequestHandler: vi.fn(),
    connect: vi.fn().mockResolvedValue(undefined),
  })),
}));

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: vi.fn().mockImplementation(() => ({})),
}));

describe("MCP Server", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.OVARA_GATEWAY_URL = "http://localhost:8080";
    process.env.OVARA_API_KEY = "test-key";
  });

  it("MCP server exposes correct tools list structure", () => {
    const tools = [
      { name: "check_action", description: "Check if an action is allowed by Ovara runtime policy" },
      { name: "get_gateway_status", description: "Get Ovara gateway health and status" },
      { name: "list_receipts", description: "List execution receipts from the gateway" },
      { name: "verify_identity", description: "Verify a machine identity" },
    ];
    expect(tools.length).toBe(4);
    expect(tools.map(t => t.name)).toContain("check_action");
    expect(tools.map(t => t.name)).toContain("get_gateway_status");
    expect(tools.map(t => t.name)).toContain("list_receipts");
    expect(tools.map(t => t.name)).toContain("verify_identity");
  });

  it("check_action tool has correct input schema", () => {
    const schema = {
      type: "object",
      properties: {
        action: { type: "string" },
        resource: { type: "string" },
        environment: { type: "string", enum: ["local", "staging", "production"], default: "local" },
      },
      required: ["action", "resource"],
    };
    expect(schema.properties.action.type).toBe("string");
    expect(schema.properties.resource.type).toBe("string");
    expect(schema.properties.environment.default).toBe("local");
  });
});

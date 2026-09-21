import { describe, it, expect, vi, beforeEach } from "vitest";
import { OvaraTool } from "../index.js";

vi.mock("../client.js", () => ({
  OvaraClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
  createClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
}));

describe("OvaraTool", () => {
  let tool: OvaraTool;

  beforeEach(() => {
    vi.clearAllMocks();
    tool = new OvaraTool({ baseUrl: "http://test:8080", apiKey: "test-key" });
  });

  it("returns allow decision for permitted action", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-1",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
    });
    (tool as any).client.check = mockCheck;

    const result = await tool.run({
      action_type: "shell.execute",
      resource: "ls -la",
      environment: "local",
    });

    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe("allow");
    expect(mockCheck).toHaveBeenCalledWith({
      actionType: "shell.execute",
      resource: "ls -la",
      environment: "local",
    });
  });

  it("returns deny decision for blocked action", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-2",
      decision: "deny",
      reason: "Not trusted",
      evaluatedAt: new Date().toISOString(),
    });
    (tool as any).client.check = mockCheck;

    const result = await tool.run({
      action_type: "git.push",
      resource: "main",
      environment: "production",
    });

    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe("deny");
    expect(parsed.reason).toBe("Not trusted");
  });

  it("handles client errors gracefully", async () => {
    const mockCheck = vi.fn().mockRejectedValue(new Error("Gateway unavailable"));
    (tool as any).client.check = mockCheck;

    await expect(
      tool.run({
        action_type: "shell.execute",
        resource: "rm -rf /",
        environment: "local",
      })
    ).rejects.toThrow("Gateway unavailable");
  });

  it("produces a valid tool definition", () => {
    const def = tool.toToolDefinition();
    expect(def.type).toBe("function");
    expect((def.function as any).name).toBe("ovara_check_action");
    expect((def.function as any).parameters.required).toContain("action_type");
  });
});

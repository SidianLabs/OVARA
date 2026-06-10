import { describe, it, expect, vi, beforeEach } from "vitest";
import { OvaraGuard } from "../index.js";

vi.mock("../client.js", () => ({
  OvaraClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
  createClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
}));

describe("OvaraGuard", () => {
  let guard: OvaraGuard;

  beforeEach(() => {
    vi.clearAllMocks();
    guard = new OvaraGuard({ baseUrl: "http://test:8080", apiKey: "test-key" });
  });

  it("returns allow decision for permitted action", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-1",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
    });
    (guard as any).client.check = mockCheck;

    const result = await guard.evaluate({
      action: "shell.execute",
      resource: "ls",
      environment: "local",
    });

    expect(result.decision).toBe("allow");
    expect(mockCheck).toHaveBeenCalledWith({
      actionType: "shell.execute",
      resource: "ls",
      environment: "local",
    });
  });

  it("returns deny decision for blocked action", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-2",
      decision: "deny",
      reason: "Production deploy blocked",
      evaluatedAt: new Date().toISOString(),
    });
    (guard as any).client.check = mockCheck;

    const result = await guard.evaluate({
      action: "deploy",
      resource: "production",
      environment: "production",
    });

    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("Production deploy blocked");
  });

  it("handles gateway errors", async () => {
    const mockCheck = vi.fn().mockRejectedValue(new Error("Connection refused"));
    (guard as any).client.check = mockCheck;

    await expect(
      guard.evaluate({ action: "shell.execute", resource: "rm" })
    ).rejects.toThrow("Connection refused");
  });

  it("produces a valid OpenAI function definition", () => {
    const def = guard.toFunctionDefinition();
    expect(def.type).toBe("function");
    expect(def.function.name).toBe("ovara_check");
    expect(def.function.parameters.required).toEqual(["action", "resource"]);
  });

  it("handles function call format for OpenAI integration", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-3",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
    });
    (guard as any).client.check = mockCheck;

    const result = await guard.handleFunctionCall({
      action: "git.push",
      resource: "main",
      environment: "staging",
    });

    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe("allow");
  });
});

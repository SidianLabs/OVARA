import { describe, it, expect, vi, beforeEach } from "vitest";
import { BrowserInterceptor } from "../index.js";

vi.mock("../client.js", () => ({
  OvaraClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
  createClient: vi.fn().mockImplementation(() => ({
    check: vi.fn(),
  })),
}));

describe("BrowserInterceptor", () => {
  let interceptor: BrowserInterceptor;

  beforeEach(() => {
    vi.clearAllMocks();
    interceptor = new BrowserInterceptor({
      baseUrl: "http://test:8080",
      apiKey: "test-key",
      blockOnDeny: true,
    });
  });

  it("allows navigation for trusted URLs", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      decision_id: "dec-1",
      decision: "allow",
      reason_codes: ["allowed"],
      requires_approval: false,
    });
    (interceptor as any).client.check = mockCheck;

    const result = await interceptor.evaluate({
      target: "navigation",
      url: "https://example.com",
      environment: "local",
    });

    expect(result.allowed).toBe(true);
    expect(result.decision).toBe("allow");
    expect(mockCheck).toHaveBeenCalledWith({
      actionType: "browser.navigate",
      resource: "https://example.com",
      environment: "local",
    });
  });

  it("blocks navigation for denied URLs", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      decision_id: "dec-2",
      decision: "deny",
      reason_codes: ["Blocked domain"],
      requires_approval: false,
    });
    (interceptor as any).client.check = mockCheck;

    const result = await interceptor.evaluate({
      target: "navigation",
      url: "https://evil.com",
      environment: "production",
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("Blocked domain");
  });

  it("fails closed on gateway errors when blockOnDeny is set", async () => {
    const mockCheck = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    (interceptor as any).client.check = mockCheck;

    const result = await interceptor.evaluate({
      target: "navigation",
      url: "https://example.com",
    });
    expect(result.allowed).toBe(false);
    expect(result.decision).toBe("deny");
    expect(result.reason).toContain("gateway_error");
  });

  it("maps form submissions to correct action type", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      decision_id: "dec-3",
      decision: "allow",
      reason_codes: ["allowed"],
      requires_approval: false,
    });
    (interceptor as any).client.check = mockCheck;

    await interceptor.evaluate({
      target: "form_submit",
      url: "https://example.com/submit",
      method: "POST",
    });

    expect(mockCheck).toHaveBeenCalledWith(
      expect.objectContaining({ actionType: "browser.form_submit" })
    );
  });

  it("maps file downloads to correct action type", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      decision_id: "dec-4",
      decision: "allow",
      reason_codes: ["allowed"],
      requires_approval: false,
    });
    (interceptor as any).client.check = mockCheck;

    await interceptor.evaluate({
      target: "file_download",
      url: "https://example.com/file.zip",
    });

    expect(mockCheck).toHaveBeenCalledWith(
      expect.objectContaining({ actionType: "browser.download" })
    );
  });
});

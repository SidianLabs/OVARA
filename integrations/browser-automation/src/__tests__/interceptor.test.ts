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
      requestId: "req-1",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
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
      requestId: "req-2",
      decision: "deny",
      reason: "Blocked domain",
      evaluatedAt: new Date().toISOString(),
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

  it("handles gateway unavailable errors", async () => {
    const mockCheck = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    (interceptor as any).client.check = mockCheck;

    await expect(
      interceptor.evaluate({
        target: "navigation",
        url: "https://example.com",
      })
    ).rejects.toThrow("ECONNREFUSED");
  });

  it("maps form submissions to correct action type", async () => {
    const mockCheck = vi.fn().mockResolvedValue({
      requestId: "req-3",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
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
      requestId: "req-4",
      decision: "allow",
      evaluatedAt: new Date().toISOString(),
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

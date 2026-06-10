import { describe, it, expect, vi, beforeEach } from "vitest";
import { OvaraClient, createClient } from "../client";

describe("OvaraClient", () => {
  let client: OvaraClient;

  beforeEach(() => {
    client = new OvaraClient({ baseUrl: "http://localhost:8080", apiKey: "test-key", retries: 0 });
  });

  it("constructs with options", () => {
    const c = new OvaraClient({ baseUrl: "http://example.com", apiKey: "key", timeoutMs: 3000, retries: 1 });
    expect(c).toBeInstanceOf(OvaraClient);
  });

  it("createClient factory works", () => {
    const c = createClient({ baseUrl: "http://localhost:8080" });
    expect(c).toBeInstanceOf(OvaraClient);
  });

  it("strips trailing slash from baseUrl", async () => {
    const c = new OvaraClient({ baseUrl: "http://localhost:8080/", retries: 0 });
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(JSON.stringify({ status: "ok" })) });
    globalThis.fetch = mockFetch as any;

    await c.health();
    expect(mockFetch).toHaveBeenCalledWith("http://localhost:8080/v1/runtime/health", expect.any(Object));
  });

  it("includes API key in headers", async () => {
    const c = new OvaraClient({ baseUrl: "http://localhost:8080", apiKey: "sk_test", retries: 0 });
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(JSON.stringify({ status: "ok" })) });
    globalThis.fetch = mockFetch as any;

    await c.health();
    const call = mockFetch.mock.calls[0];
    expect(call[1].headers).toEqual(expect.objectContaining({
      "Authorization": "Bearer sk_test",
      "Content-Type": "application/json",
    }));
  });

  it("check sends action request", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(JSON.stringify({ requestId: "req-1", decision: "allow", evaluatedAt: new Date().toISOString() })) });
    globalThis.fetch = mockFetch as any;

    const resp = await client.check({ actionType: "shell.execute", resource: "npm install", environment: "local" });
    expect(resp.decision).toBe("allow");
  });

  it("allow returns boolean", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(JSON.stringify({ requestId: "req-2", decision: "deny", evaluatedAt: new Date().toISOString() })) });
    globalThis.fetch = mockFetch as any;

    const allowed = await client.allow("sudo", "*", "local");
    expect(allowed).toBe(false);
  });

  it("retries on failure", async () => {
    const c = new OvaraClient({ baseUrl: "http://localhost:8080", retries: 2 });
    let attempt = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      attempt++;
      if (attempt < 3) return Promise.reject(new Error("network error"));
      return Promise.resolve({ ok: true, text: () => Promise.resolve(JSON.stringify({ status: "ok" })) });
    });
    globalThis.fetch = mockFetch as any;

    await c.health();
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("throws after all retries fail", async () => {
    const c = new OvaraClient({ baseUrl: "http://localhost:8080", retries: 1 });
    const mockFetch = vi.fn().mockRejectedValue(new Error("persistent error"));
    globalThis.fetch = mockFetch as any;

    await expect(c.health()).rejects.toThrow("persistent error");
  });

  it("listReceipts sends pagination params", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve(JSON.stringify([])) });
    globalThis.fetch = mockFetch as any;

    await client.listReceipts({ limit: 10, offset: 20 });
    expect(mockFetch.mock.calls[0][0]).toContain("limit=10");
    expect(mockFetch.mock.calls[0][0]).toContain("offset=20");
  });
});

import { describe, it, expect, vi } from "vitest";
import { OvaraClient } from "../client";

const ok = (body: unknown) =>
  ({ ok: true, text: () => Promise.resolve(JSON.stringify(body)) }) as any;

describe("wire format matches the gateway", () => {
  it("retries a check with a fresh nonce, so replay protection does not reject it", async () => {
    const c = new OvaraClient({ baseUrl: "http://gw", retries: 2, retryDelayMs: 0 });
    const nonces: string[] = [];
    let n = 0;
    globalThis.fetch = vi.fn().mockImplementation((_url: string, init: any) => {
      nonces.push(JSON.parse(init.body).nonce);
      if (++n < 3) return Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve("busy") });
      return Promise.resolve(ok({ decision: "allow" }));
    }) as any;

    await c.check({ actionType: "http.request" as any, resource: "GET https://a/", environment: "dev" as any });

    expect(nonces).toHaveLength(3);
    expect(new Set(nonces).size).toBe(3);
  });

  it("keeps a caller-supplied nonce across retries", async () => {
    const c = new OvaraClient({ baseUrl: "http://gw", retries: 1, retryDelayMs: 0 });
    const nonces: string[] = [];
    let n = 0;
    globalThis.fetch = vi.fn().mockImplementation((_u: string, init: any) => {
      nonces.push(JSON.parse(init.body).nonce);
      if (++n < 2) return Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve("x") });
      return Promise.resolve(ok({ decision: "allow" }));
    }) as any;

    await c.check({ actionType: "http.request" as any, resource: "r", environment: "dev" as any, nonce: "mine" });
    expect(nonces).toEqual(["mine", "mine"]);
  });

  it("sends every field of a signed delegation hop", async () => {
    const c = new OvaraClient({ baseUrl: "http://gw", retries: 0 });
    let sent: any;
    globalThis.fetch = vi.fn().mockImplementation((_u: string, init: any) => {
      sent = JSON.parse(init.body);
      return Promise.resolve(ok({ decision: "allow" }));
    }) as any;

    await c.check({
      actionType: "http.request" as any,
      resource: "r",
      environment: "dev" as any,
      delegationChain: {
        depth: 1,
        authorities: [
          {
            issuer: "root",
            subjectId: "agent",
            actions: ["http.request"],
            resourceScope: "https://api/*",
            audience: "gw",
            expiresAt: "2030-01-01T00:00:00Z",
            nonce: "n1",
            signature: "c2ln",
          },
        ],
      },
    });

    expect(sent.delegation_chain.authorities[0]).toEqual({
      issuer: "root",
      subject_id: "agent",
      actions: ["http.request"],
      resource_scope: "https://api/*",
      audience: "gw",
      expires_at: "2030-01-01T00:00:00Z",
      nonce: "n1",
      signature: "c2ln",
    });
  });

  it("unwraps the list envelopes the gateway returns", async () => {
    const c = new OvaraClient({ baseUrl: "http://gw", retries: 0 });
    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce(ok({ approvals: [{ id: "a1" }] }))
      .mockResolvedValueOnce(ok({ executions: [{ id: "e1" }], count: 1 }))
      .mockResolvedValueOnce(ok({ continuations: [{ id: "c1" }] })) as any;

    expect(await c.listApprovals()).toEqual([{ id: "a1" }]);
    expect(await c.listExecutions()).toEqual([{ id: "e1" }]);
    expect(await c.listContinuations()).toEqual([{ id: "c1" }]);
  });
});

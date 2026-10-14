import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHash } from "crypto";
import { createToolGuard, ToolDenied, ToolHeld, GuardError, toolResource, canonicalArguments, maskSecrets } from "../guard";

const TOKEN = "agent-token";

/** A stand-in for the gateway's decision API with the rules the guard relies on. */
class FakeGateway {
  requests: { method: string; path: string; body: any }[] = [];
  decisions = new Map<string, { decision: string; request: any; outcome: any }>();
  approvals = new Map<string, any>();
  human: ((a: any) => void) | null = null;
  claimConflict = false;
  outcomeStatus = 200;
  constructor(private decide: (resource: string) => string) {}

  calls(path: string) {
    return this.requests.filter((r) => r.path === path).map((r) => r.body);
  }
  paths() {
    return this.requests.map((r) => r.path);
  }

  fetch = async (url: string, init: any) => {
    const path = new URL(url).pathname;
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(init.body) : {};
    this.requests.push({ method, path, body });
    const answer = (status: number, json: any) => ({ ok: status < 300, status, text: async () => JSON.stringify(json) });
    if (init?.headers?.Authorization !== `Bearer ${TOKEN}`) return answer(401, { error: "unauthorized" });
    if (path === "/v1/runtime/check") {
      const decision = this.decide(body.resource);
      const id = `dec_${this.decisions.size + 1}`;
      this.decisions.set(id, { decision, request: body, outcome: null });
      return answer(200, { decision_id: id, decision, reason_codes: [`policy_${decision}`], requires_approval: decision === "escalate", matched_rule: decision === "escalate" ? "" : `the ${decision} rule` });
    }
    if (path === "/v1/approval/create") {
      const d = this.decisions.get(body.decision_id);
      if (!d) return answer(404, {});
      if (d.decision !== "escalate") return answer(409, {});
      const key = d.request.resource + "|" + d.request.metadata?.proxy_context?.arguments_sha256;
      for (const a of this.approvals.values()) {
        if (a._key === key && (a.status === "pending" || (a.status === "approved" && !a._claimed))) return answer(200, pub(a));
      }
      const id = `apr_${this.approvals.size + 1}`;
      const a = { approval_id: id, decision_id: body.decision_id, status: "pending", resolved_by: "", polls: 0, _key: key, _claimed: false };
      this.approvals.set(id, a);
      return answer(201, pub(a));
    }
    if (path.startsWith("/v1/approval/") && path.endsWith("/claim")) {
      const a = this.approvals.get(path.split("/")[3]);
      if (!a) return answer(404, {});
      if (this.claimConflict || a._claimed) return answer(409, {});
      if (a.status !== "approved") return answer(200, { approval_id: a.approval_id, status: a.status, claimed: false });
      a._claimed = true;
      return answer(200, { approval_id: a.approval_id, status: "approved", claimed: true });
    }
    if (path.startsWith("/v1/approval/")) {
      const a = this.approvals.get(path.split("/")[3]);
      if (!a) return answer(404, {});
      a.polls++;
      if (this.human) this.human(a);
      return answer(200, pub(a));
    }
    if (path === "/v1/runtime/outcome") {
      const d = this.decisions.get(body.decision_id);
      if (!d) return answer(404, {});
      if (d.decision === "deny" || d.outcome) return answer(409, {});
      if (this.outcomeStatus !== 200) return answer(this.outcomeStatus, {});
      d.outcome = body;
      return answer(200, { decision_id: body.decision_id, status: body.status, recorded: true });
    }
    return answer(404, { error: "no such route" });
  };
}

function pub(a: any) {
  return Object.fromEntries(Object.entries(a).filter(([k]) => !k.startsWith("_")));
}

const approveOnSecondPoll = (a: any) => {
  if (a.polls >= 2 && a.status === "pending") Object.assign(a, { status: "approved", resolved_by: "alice" });
};
const denyOnFirstPoll = (a: any) => {
  if (a.status === "pending") Object.assign(a, { status: "denied", resolved_by: "bob" });
};

function guardFor(gw: FakeGateway, extra: Record<string, unknown> = {}) {
  globalThis.fetch = gw.fetch as any;
  return createToolGuard({ baseUrl: "http://gateway.test/", apiKey: TOKEN, agent: "support-bot", framework: "vitest", waitSeconds: 5, pollMs: 1, ...extra });
}

describe("ToolGuard", () => {
  const realFetch = globalThis.fetch;
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
    warn.mockRestore();
  });

  it("runs an allowed tool and records its outcome", async () => {
    const gw = new FakeGateway(() => "allow");
    const guard = guardFor(gw);
    const ran: string[] = [];
    const sendEmail = guard.wrap("send_email", (to: string, subject: string, password: string) => {
      ran.push(to);
      return "sent";
    });
    expect(await sendEmail("a@example.com", "hi", "hunter2")).toBe("sent");
    expect(ran).toEqual(["a@example.com"]);

    const [check] = gw.calls("/v1/runtime/check");
    expect(check.action_type).toBe("tool.call");
    expect(check.resource).toBe("tool:send_email");
    expect(check.environment).toBe("local");
    expect(check.nonce).toBeTruthy();
    const ctx = check.metadata.proxy_context;
    const args = { to: "a@example.com", subject: "hi", password: "hunter2" };
    expect(ctx.tool).toBe("send_email");
    expect(ctx.agent).toBe("support-bot");
    expect(ctx.framework).toBe("vitest");
    expect(ctx.arguments_sha256).toBe(createHash("sha256").update(canonicalArguments(args)).digest("hex"));
    expect(ctx.arguments_bytes).toBe(String(Buffer.byteLength(canonicalArguments(args))));
    expect(ctx.arguments).not.toContain("hunter2");
    expect(ctx.arguments).toContain('"password":"***"');
    for (const v of Object.values(ctx)) expect(typeof v).toBe("string");

    const [outcome] = gw.calls("/v1/runtime/outcome");
    expect(outcome.decision_id).toBe("dec_1");
    expect(outcome.status).toBe("ok");
    expect(outcome.duration_ms).toBeGreaterThanOrEqual(0);
    expect(outcome.error).toBeUndefined();
    expect(guard.last?.outcomeRecorded).toBe(true);
    expect(guard.last?.rule).toBe("the allow rule");
    expect(gw.calls("/v1/approval/create")).toHaveLength(0);
  });

  it("never runs a denied tool", async () => {
    const gw = new FakeGateway(() => "deny");
    const guard = guardFor(gw);
    const ran: number[] = [];
    const del = guard.wrap("delete_everything", () => ran.push(1));
    await expect(del()).rejects.toBeInstanceOf(ToolDenied);
    await expect(del()).rejects.toThrow(/denied by policy .*the deny rule.*policy_deny/);
    expect(ran).toEqual([]);
    expect(gw.calls("/v1/runtime/outcome")).toHaveLength(0);
  });

  it("reports an error outcome when the tool throws, and rethrows", async () => {
    const gw = new FakeGateway(() => "allow");
    const guard = guardFor(gw);
    const flaky = guard.wrap("flaky", async (n: number) => {
      throw new RangeError(`boom ${n}`);
    });
    await expect(flaky(3)).rejects.toThrow("boom 3");
    const [outcome] = gw.calls("/v1/runtime/outcome");
    expect(outcome.status).toBe("error");
    expect(outcome.error).toBe("RangeError: boom 3");
    expect(gw.calls("/v1/runtime/check")[0].metadata.proxy_context.arguments).toBe('{"n":3}');
  });

  it("does not fail the call when the outcome cannot be recorded", async () => {
    const gw = new FakeGateway(() => "allow");
    gw.outcomeStatus = 500;
    const guard = guardFor(gw);
    expect(await guard.wrap("t", () => "done")()).toBe("done");
    expect(guard.last?.outcomeRecorded).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it("runs a held tool once a person approves, after claiming the approval", async () => {
    const gw = new FakeGateway(() => "escalate");
    gw.human = approveOnSecondPoll;
    const held: string[] = [];
    const guard = guardFor(gw, { onHold: (c: any) => held.push(c.approvalId) });
    const ran: string[] = [];
    const post = guard.wrap("post_tweet", (text: string) => {
      ran.push(text);
      return "posted";
    });
    expect(await post("hello")).toBe("posted");
    expect(ran).toEqual(["hello"]);
    expect(held).toEqual(["apr_1"]);
    const paths = gw.paths();
    expect(paths.filter((p) => p === "/v1/approval/apr_1/claim")).toHaveLength(1);
    expect(paths.indexOf("/v1/approval/apr_1/claim")).toBeLessThan(paths.indexOf("/v1/runtime/outcome"));
    expect(guard.last).toMatchObject({ decision: "escalate", approvalId: "apr_1", claimed: true, approvalStatus: "approved", resolvedBy: "alice", outcomeRecorded: true });
  });

  it("never runs a tool a person denies", async () => {
    const gw = new FakeGateway(() => "escalate");
    gw.human = denyOnFirstPoll;
    const guard = guardFor(gw);
    const ran: number[] = [];
    await expect(guard.wrap("wire_money", () => ran.push(1))()).rejects.toThrow(/denied by bob/);
    expect(ran).toEqual([]);
    expect(gw.paths().some((p) => p.endsWith("/claim"))).toBe(false);
  });

  it("fails fast with the approval left open", async () => {
    const gw = new FakeGateway(() => "escalate");
    const guard = guardFor(gw, { waitSeconds: 0 });
    const ran: number[] = [];
    const err = await guard.wrap("deploy", () => ran.push(1))().catch((e) => e);
    expect(err).toBeInstanceOf(ToolHeld);
    expect(err.approvalId).toBe("apr_1");
    expect(err.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(ran).toEqual([]);
    expect(gw.approvals.get("apr_1").status).toBe("pending");
  });

  it("gets a late answer back for the identical call and uses it once", async () => {
    const gw = new FakeGateway(() => "escalate");
    const guard = guardFor(gw, { waitSeconds: 0 });
    const ran: string[] = [];
    const deploy = guard.wrap("deploy", (env: string) => ran.push(env));
    await expect(deploy("prod")).rejects.toBeInstanceOf(ToolHeld);
    Object.assign(gw.approvals.get("apr_1"), { status: "approved", resolved_by: "alice" });
    await deploy("prod");
    expect(ran).toEqual(["prod"]);
    expect(guard.last).toMatchObject({ approvalId: "apr_1", claimed: true });
    const again = await deploy("prod").catch((e) => e);
    expect(again).toBeInstanceOf(ToolHeld);
    expect(again.approvalId).toBe("apr_2");
    const other = await deploy("staging").catch((e) => e);
    expect(other.approvalId).toBe("apr_3");
    expect(ran).toEqual(["prod"]);
  });

  it("does not run on an approval that was already used", async () => {
    const gw = new FakeGateway(() => "escalate");
    gw.human = approveOnSecondPoll;
    gw.claimConflict = true;
    const guard = guardFor(gw);
    const ran: number[] = [];
    await expect(guard.wrap("t", () => ran.push(1))()).rejects.toThrow(/already used/);
    expect(ran).toEqual([]);
  });

  it("fails closed when the gateway cannot be reached", async () => {
    globalThis.fetch = (async () => {
      throw new TypeError("fetch failed");
    }) as any;
    const guard = createToolGuard({ baseUrl: "http://gateway.test", apiKey: TOKEN });
    const ran: number[] = [];
    const err = await guard.wrap("t", () => ran.push(1))().catch((e) => e);
    expect(err).toBeInstanceOf(GuardError);
    expect(err.message).toMatch(/did not run/);
    expect(ran).toEqual([]);
  });

  it("fails closed when the check is rejected", async () => {
    const gw = new FakeGateway(() => "allow");
    globalThis.fetch = gw.fetch as any;
    const guard = createToolGuard({ baseUrl: "http://gateway.test", apiKey: "wrong" });
    await expect(guard.wrap("t", () => 1)()).rejects.toThrow(/HTTP 401/);
  });

  it("names positional arguments after the parameters, and passes an options object through", async () => {
    const gw = new FakeGateway(() => "allow");
    const guard = guardFor(gw);
    await guard.wrap("move", (src: string, dst: string, force = false) => [src, dst, force])("a", "b", true);
    expect(gw.calls("/v1/runtime/check")[0].metadata.proxy_context.arguments).toBe('{"dst":"b","force":true,"src":"a"}');
    await guard.wrap("query", async (opts: { sql: string; token: string }) => opts.sql)({ sql: "select 1", token: "t" });
    expect(gw.calls("/v1/runtime/check")[1].metadata.proxy_context.arguments).toBe('{"sql":"select 1","token":"***"}');
  });
});

describe("guard helpers", () => {
  it("escapes tool names like the MCP gate", () => {
    expect(toolResource("send_email")).toBe("tool:send_email");
    expect(toolResource("we ird")).toBe("tool:we%20ird");
    expect(toolResource("a/b*c")).toBe("tool:a%2Fb%2Ac");
    expect(toolResource("réglé")).toBe("tool:r%C3%A9gl%C3%A9");
  });
  it("canonicalises arguments with sorted keys and masks secrets in the preview only", () => {
    expect(canonicalArguments({ b: 1, a: [2, { d: 3, c: 4 }] })).toBe('{"a":[2,{"c":4,"d":3}],"b":1}');
    expect(canonicalArguments(undefined)).toBe("{}");
    const args = { url: "https://x", headers: { Authorization: "Bearer abc" }, items: [{ api_key: "k" }], n: 1 };
    expect(maskSecrets(args)).toEqual({ url: "https://x", headers: { Authorization: "***" }, items: [{ api_key: "***" }], n: 1 });
    expect(canonicalArguments(args)).not.toBe(canonicalArguments(maskSecrets(args)));
  });
});

import { createHash, randomUUID } from "crypto";

/**
 * A tool guard for agent frameworks.
 *
 * Every in-process tool call is decided by the Ovara gateway before it
 * runs, held for a person when policy says so, and reported afterwards, so
 * the decision and what happened share one record. The guard holds the
 * AGENT credential only: it can ask and report, never approve.
 *
 *   const guard = createToolGuard({ baseUrl, apiKey, agent: "support-bot" });
 *   const sendEmail = guard.wrap("send_email", async (to: string, body: string) => { ... });
 *
 * A denied call throws ToolDenied and the function never runs. A held call
 * opens an approval (a person sees the tool, the size and hash of its
 * arguments, and a preview with secret-looking values masked), waits
 * `waitSeconds` for the answer, then throws ToolHeld with the approval id;
 * the identical call made again gets the approval back once it is answered.
 * An approved call is claimed (single use) before it runs. The guard fails
 * closed: when the gateway cannot be reached, the tool does not run.
 */

export const TOOL_ACTION_TYPE = "tool.call";
const PREVIEW_LIMIT = 2048;
const MASK = "***";
const SECRET_KEY = /(pass(word|wd|phrase)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie|session)/i;

export interface ToolGuardOptions {
  baseUrl: string;
  apiKey?: string;
  /** The environment the decision is made for (default "local"). */
  environment?: string;
  /** The agent's name, shown with the approval. */
  agent?: string;
  /** The framework in use, shown with the approval. */
  framework?: string;
  /** How long a held call waits for a person (default 60; 0 = fail fast). */
  waitSeconds?: number;
  /** How often a held call asks after the approval (default 1000 ms). */
  pollMs?: number;
  /** Per-request timeout (default 10000 ms). */
  timeoutMs?: number;
  /** Called once when a call is held, with the approval open. */
  onHold?: (call: GuardedCall) => void;
}

/** The record of one call through the guard. */
export interface GuardedCall {
  tool: string;
  resource: string;
  argumentsSha256: string;
  argumentsBytes: number;
  decisionId: string;
  decision: string;
  rule: string;
  reasons: string[];
  approvalId: string;
  approvalStatus: string;
  resolvedBy: string;
  claimed: boolean;
  outcomeStatus: string;
  outcomeRecorded?: boolean;
  durationMs: number;
}

/** The guard could not get an answer: the tool did not run. */
export class GuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardError";
  }
}

/** The gateway, the policy or a person said no: the tool did not run. */
export class ToolDenied extends GuardError {
  readonly call: GuardedCall;
  readonly reason: string;
  constructor(call: GuardedCall, reason: string) {
    super(`tool '${call.tool}' not run: ${reason}`);
    this.name = "ToolDenied";
    this.call = call;
    this.reason = reason;
  }
}

/** The call waits on a person; `approvalId` names the approval. */
export class ToolHeld extends GuardError {
  readonly call: GuardedCall;
  readonly approvalId: string;
  readonly retryAfterSeconds: number;
  constructor(call: GuardedCall, retryAfterSeconds: number) {
    super(`tool '${call.tool}' is held for approval ${call.approvalId}: ask again after ${retryAfterSeconds}s`);
    this.name = "ToolHeld";
    this.call = call;
    this.approvalId = call.approvalId;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * The policy resource for a tool: `tool:<name>` with the MCP gate's
 * escaping (letters, digits, `_`, `-` and `.` kept, every other byte
 * `%XX`), so a name cannot carry a wildcard, a separator or white space.
 */
export function toolResource(name: string): string {
  let out = "";
  for (const b of Buffer.from(name, "utf8")) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9_.-]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return "tool:" + out;
}

/** One byte string for one set of arguments: sorted keys, no spaces. */
export function canonicalArguments(value: unknown): string {
  return canonical(value === undefined ? {} : value);
}

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") {
    return v === undefined ? "null" : JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  return (
    "{" +
    Object.keys(o)
      .sort()
      .filter((k) => o[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + canonical(o[k]))
      .join(",") +
    "}"
  );
}

/** A copy with the values of secret-looking keys replaced, at any depth. */
export function maskSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(maskSecrets);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_KEY.test(k) ? MASK : maskSecrets(v);
    }
    return out;
  }
  return value;
}

type Step = ["POST" | "GET", string, unknown] | ["sleep", number, null];
type Answer = { status: number; body: Record<string, any> };

export class ToolGuard {
  readonly options: Required<Pick<ToolGuardOptions, "environment" | "waitSeconds" | "pollMs" | "timeoutMs">> & ToolGuardOptions;
  /** The record of the last call through the guard. */
  last: GuardedCall | undefined;

  constructor(options: ToolGuardOptions) {
    this.options = {
      environment: "local",
      waitSeconds: 60,
      pollMs: 1000,
      timeoutMs: 10000,
      ...options,
      baseUrl: options.baseUrl.replace(/\/+$/, ""),
    };
  }

  /** The same function, decided before it runs and reported after. */
  wrap<A extends unknown[], R>(name: string, fn: (...args: A) => R | Promise<R>): (...args: A) => Promise<R> {
    return async (...args: A): Promise<R> => {
      const call = await this.check(name, argumentsOf(fn, args));
      const started = Date.now();
      try {
        const result = await fn(...args);
        await this.report(call, started, undefined);
        return result;
      } catch (err) {
        await this.report(call, started, err);
        throw err;
      }
    };
  }

  /** Have one call decided. Resolves when it may run; throws ToolDenied or ToolHeld when it may not. */
  async check(tool: string, args?: unknown): Promise<GuardedCall> {
    const canon = canonicalArguments(args);
    const call: GuardedCall = {
      tool,
      resource: toolResource(tool),
      argumentsSha256: createHash("sha256").update(canon, "utf8").digest("hex"),
      argumentsBytes: Buffer.byteLength(canon, "utf8"),
      decisionId: "",
      decision: "",
      rule: "",
      reasons: [],
      approvalId: "",
      approvalStatus: "",
      resolvedBy: "",
      claimed: false,
      outcomeStatus: "",
      durationMs: 0,
    };
    this.last = call;
    const steps = this.protocol(call, this.checkBody(call, args));
    let next = steps.next();
    while (!next.done) {
      const step = next.value;
      if (step[0] === "sleep") {
        await new Promise((r) => setTimeout(r, step[1]));
        next = steps.next({ status: 0, body: {} });
      } else {
        next = steps.next(await this.request(step[0], step[1], step[2]));
      }
    }
    return call;
  }

  private *protocol(call: GuardedCall, checkBody: unknown): Generator<Step, void, Answer> {
    const d = yield ["POST", "/v1/runtime/check", checkBody];
    if (d.status !== 200) {
      throw new GuardError(`tool '${call.tool}' not run: the gateway answered HTTP ${d.status} to the check`);
    }
    call.decisionId = String(d.body.decision_id ?? "");
    call.decision = String(d.body.decision ?? "");
    call.rule = String(d.body.matched_rule ?? "");
    call.reasons = Array.isArray(d.body.reason_codes) ? d.body.reason_codes.map(String) : [];
    if (call.decision === "allow") return;
    if (call.decision !== "escalate") throw new ToolDenied(call, why(call, "denied by policy"));

    const a = yield ["POST", "/v1/approval/create", { decision_id: call.decisionId }];
    if (a.status !== 200 && a.status !== 201) {
      throw new ToolDenied(call, `held for a person, but no approval could be opened (HTTP ${a.status})`);
    }
    call.approvalId = String(a.body.approval_id ?? "");
    call.approvalStatus = String(a.body.status ?? "pending");
    call.resolvedBy = String(a.body.resolved_by ?? "");
    if (call.approvalStatus === "pending" && this.options.onHold) this.options.onHold(call);
    const deadline = Date.now() + Math.max(this.options.waitSeconds, 0) * 1000;
    while (call.approvalStatus === "pending") {
      if (Date.now() >= deadline) throw new ToolHeld(call, Math.max(this.options.pollMs / 1000, 1));
      yield ["sleep", Math.min(this.options.pollMs, Math.max(deadline - Date.now(), 0)), null];
      const p = yield ["GET", `/v1/approval/${call.approvalId}`, undefined];
      if (p.status === 200) {
        call.approvalStatus = String(p.body.status ?? "pending");
        call.resolvedBy = String(p.body.resolved_by ?? "");
      } else if (p.status === 404) {
        throw new ToolDenied(call, "the approval is gone");
      }
    }
    if (call.approvalStatus !== "approved") {
      throw new ToolDenied(call, call.approvalStatus + (call.resolvedBy ? ` by ${call.resolvedBy}` : ""));
    }
    const c = yield ["POST", `/v1/approval/${call.approvalId}/claim`, undefined];
    if (c.status === 200 && c.body.claimed === true) {
      call.claimed = true;
      return;
    }
    if (c.status === 409) throw new ToolDenied(call, "the approval was already used: ask again");
    throw new ToolDenied(call, `the approval could not be claimed (status ${c.body.status ?? c.status})`);
  }

  private async report(call: GuardedCall, started: number, err: unknown): Promise<void> {
    call.durationMs = Date.now() - started;
    call.outcomeStatus = err === undefined ? "ok" : "error";
    const body: Record<string, unknown> = { decision_id: call.decisionId, status: call.outcomeStatus, duration_ms: call.durationMs };
    if (err !== undefined) {
      const e = err as { name?: string; message?: string };
      body.error = `${e?.name || "Error"}: ${e?.message ?? String(err)}`.slice(0, 600);
    }
    try {
      const r = await this.request("POST", "/v1/runtime/outcome", body);
      call.outcomeRecorded = r.status === 200;
    } catch {
      call.outcomeRecorded = false;
    }
    if (!call.outcomeRecorded) {
      console.warn(`ovara: outcome of tool '${call.tool}' (decision ${call.decisionId}) was not recorded`);
    }
  }

  private checkBody(call: GuardedCall, args: unknown): Record<string, unknown> {
    const context: Record<string, string> = {
      tool: call.tool,
      arguments: preview(args),
      arguments_bytes: String(call.argumentsBytes),
      arguments_sha256: call.argumentsSha256,
    };
    if (this.options.framework) context.framework = this.options.framework;
    if (this.options.agent) context.agent = this.options.agent;
    return {
      action_type: TOOL_ACTION_TYPE,
      resource: call.resource,
      environment: this.options.environment,
      metadata: { proxy_context: context },
      nonce: randomUUID(),
      issued_at: new Date().toISOString(),
    };
  }

  private async request(method: "POST" | "GET", path: string, body: unknown): Promise<Answer> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.options.apiKey) headers["Authorization"] = `Bearer ${this.options.apiKey}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs);
    let res: Response;
    try {
      res = await fetch(`${this.options.baseUrl}${path}`, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
    } catch (err) {
      throw new GuardError(`the gateway could not be reached (${(err as Error)?.name ?? "error"}): the tool did not run`);
    } finally {
      clearTimeout(timer);
    }
    const text = await res.text();
    let parsed: Record<string, any> = {};
    try {
      const v = text ? JSON.parse(text) : {};
      if (v && typeof v === "object" && !Array.isArray(v)) parsed = v;
    } catch {
      parsed = {};
    }
    return { status: res.status, body: parsed };
  }
}

export function createToolGuard(options: ToolGuardOptions): ToolGuard {
  return new ToolGuard(options);
}

function why(call: GuardedCall, fallback: string): string {
  const parts: string[] = [];
  if (call.rule) parts.push(`rule '${call.rule}'`);
  if (call.reasons.length) parts.push(call.reasons.join(", "));
  return parts.length ? `${fallback} (${parts.join("; ")})` : fallback;
}

function preview(args: unknown): string {
  if (args === undefined || args === null) return "";
  const text = JSON.stringify(sortKeys(maskSecrets(args)));
  return text.length > PREVIEW_LIMIT ? text.slice(0, PREVIEW_LIMIT) + "…" : text;
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = sortKeys(o[k]);
    return out;
  }
  return v;
}

/** Positional arguments named after the function's parameters when they can be read. */
function argumentsOf(fn: (...args: any[]) => unknown, args: unknown[]): unknown {
  if (args.length === 1 && args[0] && typeof args[0] === "object" && !Array.isArray(args[0])) {
    return args[0];
  }
  const names = parameterNames(fn);
  if (names.length >= args.length && names.length > 0) {
    const out: Record<string, unknown> = {};
    args.forEach((a, i) => (out[names[i]] = a));
    return out;
  }
  return { args };
}

function parameterNames(fn: (...args: any[]) => unknown): string[] {
  const src = Function.prototype.toString.call(fn);
  const m = src.match(/^(?:async\s*)?(?:function\s*[^(]*)?\(([^)]*)\)/) || src.match(/^(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/);
  if (!m) return [];
  return m[1]
    .split(",")
    .map((s) => s.trim().replace(/=.*$/, "").trim())
    .filter((s) => s && /^[A-Za-z_$][\w$]*$/.test(s));
}

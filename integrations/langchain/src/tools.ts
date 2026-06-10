interface ToolResult {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  _call: (input: Record<string, unknown>) => Promise<string>;
}

const OVARA_URL = process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
const OVARA_KEY = process.env.OVARA_API_KEY || "";

async function callGateway(path: string, body?: Record<string, unknown>): Promise<unknown> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (OVARA_KEY) headers["Authorization"] = `Bearer ${OVARA_KEY}`;
  const res = await fetch(`${OVARA_URL}${path}`, {
    method: body ? "POST" : "GET",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`Gateway ${res.status}`);
  return res.json();
}

export const OvaraCheckTool: ToolResult = {
  name: "ovara_check_action",
  description: "Check if an action is allowed by Ovara runtime trust policy before executing it.",
  schema: {
    type: "object",
    properties: {
      action: { type: "string", description: "Action type (shell.execute, git.push, etc.)" },
      resource: { type: "string", description: "Target resource (command, branch, etc.)" },
      environment: { type: "string", enum: ["local", "staging", "production"], default: "local" },
    },
    required: ["action", "resource"],
  },
  async _call(input: Record<string, unknown>): Promise<string> {
    const result = await callGateway("/v1/runtime/check", {
      action_type: input.action,
      resource: input.resource,
      environment: input.environment || "local",
    });
    return JSON.stringify(result);
  },
};

export const OvaraStatusTool: ToolResult = {
  name: "ovara_gateway_status",
  description: "Get the current health and status of the Ovara gateway.",
  schema: { type: "object", properties: {} },
  async _call(): Promise<string> {
    const status = await callGateway("/v1/runtime/status");
    return JSON.stringify(status);
  },
};

export const OvaraReceiptsTool: ToolResult = {
  name: "ovara_list_receipts",
  description: "List recent execution receipts from the Ovara gateway.",
  schema: {
    type: "object",
    properties: {
      limit: { type: "number", default: 20 },
      offset: { type: "number", default: 0 },
    },
  },
  async _call(input: Record<string, unknown>): Promise<string> {
    const receipts = await callGateway(
      `/v1/runtime/receipts?limit=${input.limit || 20}&offset=${input.offset || 0}`
    );
    return JSON.stringify(receipts);
  },
};
